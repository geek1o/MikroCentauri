package api

import (
	"errors"
	"net/http"
	"sort"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/rulesets"
)

// DraftPolicyRequest is editable directly from the redacted GET projection.
// Credentials and operator paths are retained exclusively on the server.
type DraftPolicyRequest struct {
	DraftRevision uint64             `json:"draft_revision"`
	Mode          string             `json:"mode"`
	Groups        []coreconfig.Group `json:"groups"`
	Policy        PolicyPreview      `json:"policy"`
}
type ProxyImportRequest struct {
	DraftRevision uint64   `json:"draft_revision"`
	URIs          []string `json:"uris"`
}
type DraftPolicyResult struct {
	DraftRevision uint64                  `json:"draft_revision"`
	BaseRevision  uint64                  `json:"base_revision"`
	Model         coreconfig.ModelPreview `json:"model"`
	Policy        PolicyPreview           `json:"policy"`
}

func (s *Server) editableModel(sequence uint64) (coreconfig.Model, uint64, error) {
	view := s.view()
	if view.Pending || (s.draft == nil && sequence != 0) || (s.draft != nil && sequence != s.draft.Sequence) {
		return coreconfig.Model{}, 0, errors.New("stale draft")
	}
	if s.draft == nil {
		m, e := s.model()
		return m, view.Revision, e
	}
	if s.draft.BaseRevision == view.Revision {
		m, e := s.draft.Model.Clone()
		return m, view.Revision, e
	}
	// A committed draft remains the audit record. The next CAS edit may start
	// from its exact private committed model, without requiring credentials to
	// be resubmitted or rebasing the durable record before the new save succeeds.
	if s.draft.Restore != nil || view.Revision != s.draft.BaseRevision+1 {
		return coreconfig.Model{}, 0, errors.New("stale draft")
	}
	m, e := s.model()
	if e != nil || modelDigest(m) != modelDigest(s.draft.Model) {
		return coreconfig.Model{}, 0, errors.New("stale draft")
	}
	return m, view.Revision, nil
}

func mergePolicy(m coreconfig.Model, in DraftPolicyRequest) (coreconfig.Model, error) {
	urls := map[string]string{}
	for _, group := range m.Groups {
		urls[group.ID] = group.URL
	}
	m.Mode = in.Mode
	m.Groups = append([]coreconfig.Group(nil), in.Groups...)
	for i, group := range m.Groups {
		if group.URL != "" {
			return m, errors.New("policy cannot supply private URL")
		}
		m.Groups[i].URL = urls[group.ID]
	}
	private := map[string]rulesets.Spec{}
	for _, ref := range m.RuleSets {
		private[ref.ID] = ref
	}
	m.RuleSets = nil
	seen := map[string]bool{}
	for _, ref := range in.Policy.RuleSets {
		original, found := private[ref.ID]
		if !found || seen[ref.ID] || ref.Format != original.Format {
			return m, errors.New("unknown rule-set source")
		}
		seen[ref.ID] = true
		m.RuleSets = append(m.RuleSets, original)
	}
	m.Rules = in.Policy.Rules
	m.Services = in.Policy.Services
	m.SourceDirect = in.Policy.SourceDirect
	m.SourceProxy = in.Policy.SourceProxy
	m.DefaultOutbound = in.Policy.DefaultOutbound
	m.DNS.Bootstrap = in.Policy.DNS.Bootstrap
	m.DNS.FakeIPRange = in.Policy.DNS.FakeIPRange
	m.DNS.SelectedDomains = in.Policy.DNS.Domains
	m.DNS.SelectedSuffixes = in.Policy.DNS.Suffixes
	return m, m.Validate()
}

// policyWorkflow is called under the Server mutation mutex. Saving a policy is
// schema validation only; generation and network mutation use the normal plan.
func (s *Server) policyWorkflow(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if s.proxyWorkflow(w, r, raw, id) {
		return true
	}
	if r.URL.Path != "/api/v1/config/draft/policy" && r.URL.Path != "/api/v1/proxies/import" {
		return false
	}
	if r.URL.Path == "/api/v1/config/draft/policy" {
		var input DraftPolicyRequest
		if decode(raw, &input) != nil {
			reject(w, 400, "invalid_request")
			return true
		}
		m, revision, e := s.editableModel(input.DraftRevision)
		if e != nil {
			reject(w, 409, "stale_draft")
			return true
		}
		m, e = mergePolicy(m, input)
		if e != nil {
			reject(w, 400, "invalid_policy")
			return true
		}
		if s.view().Revision != revision || s.view().Pending {
			reject(w, 409, "stale_draft")
			return true
		}
		if s.saveDraft(m) != nil {
			reject(w, 503, "draft_persistence_failed")
			return true
		}
		s.event("policy_draft_saved", id)
		reply(w, 200, DraftPolicyResult{s.draft.Sequence, s.draft.BaseRevision, m.Preview(), policyPreview(m)})
		return true
	}
	var input ProxyImportRequest
	if decode(raw, &input) != nil || len(input.URIs) < 1 || len(input.URIs) > 128 {
		reject(w, 400, "invalid_request")
		return true
	}
	m, revision, e := s.editableModel(input.DraftRevision)
	if e != nil {
		reject(w, 409, "stale_draft")
		return true
	}
	nodes := map[string]endpoints.Endpoint{}
	for _, uri := range input.URIs {
		node, e := endpoints.ParseURI(uri)
		if e != nil {
			reject(w, 400, "invalid_endpoint_uri")
			return true
		}
		node.Enabled = true
		nodes[node.ID] = node
	}
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		node := nodes[id]
		found := false
		for i, old := range m.Endpoints {
			if old.ID == id {
				m.Endpoints[i] = node
				found = true
				break
			}
		}
		if !found {
			m.Endpoints = append(m.Endpoints, node)
		}
	}
	if m.Validate() != nil || s.validate(r.Context(), revision, m) != nil {
		reject(w, 400, "invalid_model")
		return true
	}
	if s.view().Revision != revision || s.view().Pending {
		reject(w, 409, "stale_draft")
		return true
	}
	if s.saveDraft(m) != nil {
		reject(w, 503, "draft_persistence_failed")
		return true
	}
	s.event("proxy_imported_to_draft", id)
	reply(w, 200, SubscriptionImportResult{s.draft.Sequence, s.draft.BaseRevision, len(nodes)})
	return true
}
