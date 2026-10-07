package api

import (
	"encoding/json"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"strings"
	"testing"
)

func TestProxyEditsPreserveSecretsAndCanonicalReferenceIdentity(t *testing.T) {
	m := fixture(t)
	old := m.Endpoints[0].ID
	m.Groups[0].Selected = old
	runtime := &fakeRuntime{m: m, v: RuntimeView{Ready: true}}
	s, _, token := setup(t, runtime)
	name := "Renamed proxy"
	response := call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{ID: old, Name: &name})
	if response.Code != 200 || s.draft.Model.Endpoints[0].Password != m.Endpoints[0].Password || s.draft.Model.Endpoints[0].ID != old || runtime.calls != 0 {
		t.Fatal(response.Code, response.Body.String())
	}
	uri := "trojan://rotated-private-credential@example.net:443#private-name"
	response = call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{DraftRevision: s.draft.Sequence, ID: old, URI: &uri})
	if response.Code != 200 || strings.Contains(response.Body.String(), "rotated-private-credential") || runtime.calls != 0 {
		t.Fatal(response.Code, response.Body.String())
	}
	next := s.draft.Model.Endpoints[0]
	if next.ID == old || next.Name != name || next.Password != "rotated-private-credential" || s.draft.Model.Groups[0].Members[0] != next.ID || s.draft.Model.Groups[0].Selected != next.ID {
		t.Fatal("URI replacement lost canonical identity or references")
	}
	before := s.draft.Sequence
	if call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{ID: next.ID, Name: &name}).Code != 409 || s.draft.Sequence != before {
		t.Fatal("stale edit accepted")
	}
	disabled := false
	if call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{DraftRevision: before, ID: next.ID, Enabled: &disabled}).Code != 400 || s.draft.Sequence != before {
		t.Fatal("disabled referenced node silently rewrote policy")
	}
	if call(s, "POST", "/api/v1/proxies/delete", token, ProxyDeleteRequest{DraftRevision: before, ID: next.ID}).Code != 400 || s.draft.Sequence != before {
		t.Fatal("deleted referenced node silently rewrote policy")
	}
	malformed := "trojan://secret-invalid"
	response = call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{DraftRevision: before, ID: next.ID, URI: &malformed})
	if response.Code != 400 || strings.Contains(response.Body.String(), "secret-invalid") || s.draft.Sequence != before {
		t.Fatal("failed edit leaked credentials or changed draft")
	}
}
func TestUnusedProxyDisableEnableDeleteAndTypedContracts(t *testing.T) {
	m := fixture(t)
	node, _ := endpoints.ParseURI("trojan://unused-private-password@unused.example:443#unused")
	m.Endpoints = append(m.Endpoints, node)
	runtime := &fakeRuntime{m: m, v: RuntimeView{Ready: true}}
	s, _, token := setup(t, runtime)
	raw, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(raw, &spec)
	off := false
	response := call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{ID: node.ID, Enabled: &off})
	contractResponse(t, spec, "POST", "/api/v1/proxies/update", response)
	if response.Code != 200 || s.draft.Model.Endpoints[1].Enabled || s.draft.Model.Preview().Endpoints[1].Enabled {
		t.Fatal("disabled state missing from projection")
	}
	on := true
	response = call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{DraftRevision: s.draft.Sequence, ID: node.ID, Enabled: &on})
	if response.Code != 200 || !s.draft.Model.Endpoints[1].Enabled {
		t.Fatal(response.Code, response.Body.String())
	}
	response = call(s, "POST", "/api/v1/proxies/delete", token, ProxyDeleteRequest{DraftRevision: s.draft.Sequence, ID: node.ID})
	contractResponse(t, spec, "POST", "/api/v1/proxies/delete", response)
	if response.Code != 200 || len(s.draft.Model.Endpoints) != 1 || runtime.calls != 0 {
		t.Fatal(response.Code, response.Body.String())
	}
	response = call(s, "POST", "/api/v1/proxies/delete", token, ProxyDeleteRequest{DraftRevision: s.draft.Sequence, ID: node.ID})
	if response.Code != 404 {
		t.Fatal("missing endpoint deletion accepted")
	}
}
func TestReplacementRejectsCanonicalCollision(t *testing.T) {
	m := fixture(t)
	node, _ := endpoints.ParseURI("trojan://other-private-password@other.example:443#other")
	m.Endpoints = append(m.Endpoints, node)
	s, _, token := setup(t, &fakeRuntime{m: m, v: RuntimeView{Ready: true}})
	uri := "trojan://other-private-password@other.example:443#duplicate"
	w := call(s, "POST", "/api/v1/proxies/update", token, ProxyUpdateRequest{ID: m.Endpoints[0].ID, URI: &uri})
	if w.Code != 400 || s.draft != nil {
		t.Fatal("duplicate canonical identity persisted")
	}
}
func TestEndpointReferenceReplacementIncludesRuleAndSourceTargets(t *testing.T) {
	m := coreconfig.Model{DefaultOutbound: "old", Groups: []coreconfig.Group{{Members: []string{"old", "direct"}, Selected: "old"}}, Rules: []coreconfig.Rule{{Outbound: "old"}}, SourceProxy: []coreconfig.SourcePolicy{{Outbound: "old"}}}
	replaceEndpointReferences(&m, "old", "next")
	if m.DefaultOutbound != "next" || m.Groups[0].Members[0] != "next" || m.Groups[0].Members[1] != "direct" || m.Groups[0].Selected != "next" || m.Rules[0].Outbound != "next" || m.SourceProxy[0].Outbound != "next" {
		t.Fatal("reference incomplete")
	}
}

func TestProxyOptionalFieldsRejectExplicitNull(t *testing.T) {
	s, _, token := setup(t, &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}})
	for _, name := range []string{"uri", "enabled", "name"} {
		input := map[string]any{"draft_revision": 0, "id": fixture(t).Endpoints[0].ID, "name": "unchanged", name: nil}
		if call(s, "POST", "/api/v1/proxies/update", token, input).Code != 400 || s.draft != nil {
			t.Fatal("optional null accepted", name)
		}
	}
}
