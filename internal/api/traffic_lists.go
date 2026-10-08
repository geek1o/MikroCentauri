package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/trafficlists"
)

type TrafficListRequest struct {
	DraftRevision uint64             `json:"draft_revision"`
	IDs           []string           `json:"ids"`
	Outbound      string             `json:"outbound"`
	Custom        *trafficlists.Spec `json:"custom,omitempty"`
}
type TrafficListResult struct {
	DraftRevision uint64 `json:"draft_revision"`
	BaseRevision  uint64 `json:"base_revision"`
	Imported      int    `json:"imported"`
	DomainCount   int    `json:"domain_count"`
}

func (s *Server) trafficListsPost(w http.ResponseWriter, r *http.Request, raw []byte, requestID string) bool {
	if r.URL.Path != "/api/v1/traffic-lists/import" {
		return false
	}
	var in TrafficListRequest
	if decode(raw, &in) != nil || len(in.IDs) > 16 || (len(in.IDs) == 0 && in.Custom == nil) {
		reject(w, 400, "invalid_request")
		return true
	}
	m, base, e := s.editableModel(in.DraftRevision)
	if e != nil {
		reject(w, 409, "stale_draft")
		return true
	}
	// Check the chosen outbound before making any external requests.
	check := coreconfig.Rule{ID: "list-validation", Suffixes: []string{"list.example"}, Outbound: in.Outbound}
	candidate, _ := m.Clone()
	candidate.Rules = append(candidate.Rules, check)
	if candidate.Validate() != nil {
		reject(w, 400, "invalid_policy")
		return true
	}
	specs := []trafficlists.Spec{}
	seen := map[string]bool{}
	for _, id := range in.IDs {
		if seen[id] {
			reject(w, 400, "invalid_list_source")
			return true
		}
		seen[id] = true
		found := false
		for _, entry := range trafficlists.Catalog() {
			if entry.ID == id {
				specs = append(specs, trafficlists.Spec{ID: id, Name: entry.Name, URL: entry.URL})
				found = true
				break
			}
		}
		if !found {
			snapshot, e := s.opts.TrafficLists.Load(id)
			if e != nil {
				reject(w, 400, "invalid_list_source")
				return true
			}
			specs = append(specs, snapshot.Spec)
		}
	}
	if in.Custom != nil {
		if seen[in.Custom.ID] || !trafficlists.ValidSpec(*in.Custom) {
			reject(w, 400, "invalid_list_source")
			return true
		}
		// A custom URL may not replace the source identity of a built-in catalog entry.
		for _, entry := range trafficlists.Catalog() {
			if entry.ID == in.Custom.ID {
				reject(w, 400, "invalid_list_source")
				return true
			}
		}
		specs = append(specs, *in.Custom)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	// Downloads must not hold the API mutation lock or stall health reads.
	snapshots, fetchErr := func() ([]trafficlists.Snapshot, error) {
		s.mu.Unlock()
		defer s.mu.Lock()
		snapshots := []trafficlists.Snapshot{}
		for _, spec := range specs {
			snapshot, e := s.opts.TrafficLists.Refresh(ctx, spec)
			if e != nil {
				return nil, e
			}
			snapshots = append(snapshots, snapshot)
		}
		return snapshots, nil
	}()
	if fetchErr != nil {
		code := fetchErr.Error()
		if !strings.HasPrefix(code, "list_") && code != "empty_domain_list" && code != "invalid_domain_list" {
			code = "list_download_failed"
		}
		reject(w, 422, code)
		return true
	}
	// Another request may have edited or applied a draft while sources downloaded.
	m, recheckedBase, e := s.editableModel(in.DraftRevision)
	if e != nil || recheckedBase != base {
		reject(w, 409, "stale_draft")
		return true
	}
	result, e := installListSnapshots(m, in.Outbound, snapshots)
	if e != nil {
		reject(w, 400, "list_domain_limit")
		return true
	}
	if s.view().Revision != base || s.view().Pending {
		reject(w, 409, "stale_draft")
		return true
	}
	if s.saveDraft(result) != nil {
		reject(w, 503, "draft_persistence_failed")
		return true
	}
	s.event("traffic_lists_imported_to_draft", requestID)
	reply(w, 200, TrafficListResult{s.draft.Sequence, base, len(snapshots), len(result.DNS.SelectedDomains)})
	return true
}
func installListSnapshots(m coreconfig.Model, outbound string, snapshots []trafficlists.Snapshot) (coreconfig.Model, error) {
	selected := map[string]bool{}
	for _, d := range m.DNS.SelectedDomains {
		selected[d] = true
	}
	for _, snapshot := range snapshots {
		rule := coreconfig.Rule{ID: "list-" + snapshot.Spec.ID, Name: snapshot.Spec.Name, Suffixes: append([]string{}, snapshot.Domains...), Outbound: outbound, Priority: 100}
		replaced := false
		for i, old := range m.Rules {
			if old.ID == rule.ID {
				rule.Priority = old.Priority
				rule.Enabled = old.Enabled
				m.Rules[i] = rule
				replaced = true
				break
			}
		}
		if !replaced {
			m.Rules = append(m.Rules, rule)
		}
		// Reserve only literal names. Suffix policy is preserved for SOCKS and for
		// already admitted native names; this does not authorize a wildcard allocator.
		for _, d := range snapshot.Domains {
			selected[d] = true
		}
	}
	if len(selected) > 4096 {
		return m, errors.New("list_domain_limit")
	}
	m.DNS.SelectedDomains = []string{}
	for d := range selected {
		m.DNS.SelectedDomains = append(m.DNS.SelectedDomains, d)
	}
	sort.Strings(m.DNS.SelectedDomains)
	return m, m.Validate()
}
