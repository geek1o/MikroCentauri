package api

import (
	"bytes"
	"encoding/json"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"net/http"
	"strings"
)

// ProxyUpdateRequest never returns credentials. Omitted fields retain private
// values; a new URI changes the canonical identity and rewrites references.
type ProxyUpdateRequest struct {
	DraftRevision uint64  `json:"draft_revision"`
	ID            string  `json:"id"`
	Name          *string `json:"name,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	URI           *string `json:"uri,omitempty"`
}
type ProxyDeleteRequest struct {
	DraftRevision uint64 `json:"draft_revision"`
	ID            string `json:"id"`
}
type ProxyChangeResult struct {
	DraftRevision uint64                  `json:"draft_revision"`
	BaseRevision  uint64                  `json:"base_revision"`
	ID            string                  `json:"id"`
	Model         coreconfig.ModelPreview `json:"model"`
	Policy        PolicyPreview           `json:"policy"`
}

func replaceEndpointReferences(m *coreconfig.Model, old, next string) {
	replace := func(v *string) {
		if *v == old {
			*v = next
		}
	}
	for i := range m.Groups {
		for j := range m.Groups[i].Members {
			replace(&m.Groups[i].Members[j])
		}
		replace(&m.Groups[i].Selected)
	}
	for i := range m.Rules {
		replace(&m.Rules[i].Outbound)
	}
	for i := range m.SourceProxy {
		replace(&m.SourceProxy[i].Outbound)
	}
	replace(&m.DefaultOutbound)
}
func (s *Server) proxyWorkflow(w http.ResponseWriter, r *http.Request, raw []byte, requestID string) bool {
	deleting := r.URL.Path == "/api/v1/proxies/delete"
	if !deleting && r.URL.Path != "/api/v1/proxies/update" {
		return false
	}
	var input ProxyUpdateRequest
	if deleting {
		var in ProxyDeleteRequest
		if decode(raw, &in) != nil {
			reject(w, 400, "invalid_request")
			return true
		}
		input.DraftRevision, input.ID = in.DraftRevision, in.ID
	} else if decode(raw, &input) != nil || (input.Name == nil && input.Enabled == nil && input.URI == nil) {
		reject(w, 400, "invalid_request")
		return true
	}
	if !deleting {
		var fields map[string]json.RawMessage
		json.Unmarshal(raw, &fields)
		for _, key := range []string{"name", "enabled", "uri"} {
			if value, exists := fields[key]; exists && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				reject(w, 400, "invalid_request")
				return true
			}
		}
	}
	if input.ID == "" || len(input.ID) > 64 || (input.Name != nil && (len(*input.Name) > 256 || strings.ContainsAny(*input.Name, "\x00\r\n"))) {
		reject(w, 400, "invalid_request")
		return true
	}
	m, rev, e := s.editableModel(input.DraftRevision)
	if e != nil {
		reject(w, 409, "stale_draft")
		return true
	}
	found := false
	nextID := input.ID
	for i, old := range m.Endpoints {
		if old.ID != input.ID {
			continue
		}
		found = true
		if deleting {
			m.Endpoints = append(m.Endpoints[:i], m.Endpoints[i+1:]...)
			break
		}
		next := old
		if input.URI != nil {
			parsed, err := endpoints.ParseURI(*input.URI)
			if err != nil {
				reject(w, 400, "invalid_endpoint_uri")
				return true
			}
			next = parsed
			next.Enabled = old.Enabled
			next.Name = old.Name
		}
		if input.Name != nil {
			next.Name = *input.Name
		}
		if input.Enabled != nil {
			next.Enabled = *input.Enabled
		}
		m.Endpoints[i] = next
		nextID = next.ID
		if next.ID != old.ID {
			replaceEndpointReferences(&m, old.ID, next.ID)
		}
		break
	}
	if !found {
		for i, old := range m.WireGuard {
			if old.ID != input.ID {
				continue
			}
			found = true
			if input.URI != nil {
				reject(w, 400, "wireguard_uri_unsupported")
				return true
			}
			if deleting {
				m.WireGuard = append(m.WireGuard[:i], m.WireGuard[i+1:]...)
				break
			}
			if input.Name != nil {
				m.WireGuard[i].Name = *input.Name
			}
			if input.Enabled != nil {
				m.WireGuard[i].Enabled = *input.Enabled
			}
			break
		}
	}
	if !found {
		reject(w, 404, "endpoint_absent")
		return true
	}
	if m.Validate() != nil || s.validate(r.Context(), rev, m) != nil {
		reject(w, 400, "invalid_model")
		return true
	}
	if s.view().Revision != rev || s.view().Pending {
		reject(w, 409, "stale_draft")
		return true
	}
	if s.saveDraft(m) != nil {
		reject(w, 503, "draft_persistence_failed")
		return true
	}
	code := "proxy_updated_in_draft"
	if deleting {
		code = "proxy_deleted_from_draft"
	}
	s.event(code, requestID)
	reply(w, 200, ProxyChangeResult{s.draft.Sequence, s.draft.BaseRevision, nextID, m.Preview(), policyPreview(m)})
	return true
}
