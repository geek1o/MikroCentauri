package api

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/rulesets"
)

func policyCall(s *Server, path string, input any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(input)
	r := httptest.NewRequest("POST", path, nil)
	w := httptest.NewRecorder()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.policyWorkflow(w, r, raw, "request-policy") {
		panic("unhandled policy route")
	}
	return w
}
func TestPolicyDraftUsesRedactedProjectionAndRetainsPrivateFields(t *testing.T) {
	m := fixture(t)
	m.Groups[0].URL = "https://probe.example/check?private-canary-token"
	m.RuleSets = []rulesets.Spec{{ID: "remote-set", URL: "https://rules.example/private-source-token", Format: "source"}}
	runtime := &fakeRuntime{m: m, v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, runtime)
	projected := call(s, "GET", "/api/v1/config", token, nil)
	var projection struct {
		Model  coreconfig.ModelPreview `json:"model"`
		Policy PolicyPreview           `json:"policy"`
	}
	if json.Unmarshal(projected.Body.Bytes(), &projection) != nil {
		t.Fatal(projected.Body.String())
	}
	if strings.Contains(projected.Body.String(), "secret-password") || strings.Contains(projected.Body.String(), "private-canary-token") || strings.Contains(projected.Body.String(), "private-source-token") {
		t.Fatal("private model in GET")
	}
	projection.Policy.Rules = []coreconfig.Rule{{ID: "direct-rule", Domains: []string{"example.org"}, Outbound: "direct"}}
	in := DraftPolicyRequest{Mode: projection.Model.Mode, Groups: projection.Model.Groups, Policy: projection.Policy}
	w := policyCall(s, "/api/v1/config/draft/policy", in)
	if w.Code != 200 || s.draft == nil || strings.Contains(w.Body.String(), "secret-password") || strings.Contains(w.Body.String(), "private-") {
		t.Fatal(w.Code, w.Body.String())
	}
	after := s.draft.Model
	if !reflect.DeepEqual(after.Endpoints, m.Endpoints) || !reflect.DeepEqual(after.WireGuard, m.WireGuard) || after.DNS.CachePath != m.DNS.CachePath || after.Groups[0].URL != m.Groups[0].URL || !reflect.DeepEqual(after.RuleSets, m.RuleSets) {
		t.Fatal("private fields changed during projection edit")
	}
	if len(after.Rules) != 1 || runtime.checks != 0 || runtime.calls != 0 {
		t.Fatal("policy save generated/applied network", runtime.checks, runtime.calls)
	}
	w = policyCall(s, "/api/v1/config/draft/policy", in)
	if w.Code != 409 {
		t.Fatal("stale zero draft revision accepted")
	}
	in.DraftRevision = s.draft.Sequence
	in.Groups[0].URL = "https://attacker.example/private-token"
	w = policyCall(s, "/api/v1/config/draft/policy", in)
	if w.Code != 400 || strings.Contains(w.Body.String(), "private-token") {
		t.Fatal("URL supplied through public policy")
	}
}
func TestPolicyDraftRejectsUnknownRuleSetReferencesAndMalformedCAS(t *testing.T) {
	s, _, _ := setup(t, nil)
	m := fixture(t)
	input := DraftPolicyRequest{Mode: m.Mode, Groups: m.Preview().Groups, Policy: policyPreview(m)}
	input.Policy.RuleSets = []RuleSetReference{{ID: "unknown", Format: "source"}}
	if policyCall(s, "/api/v1/config/draft/policy", input).Code != 400 || s.draft != nil {
		t.Fatal("private source reference invented")
	}
	input.Policy.RuleSets = nil
	input.DraftRevision = 9
	if policyCall(s, "/api/v1/config/draft/policy", input).Code != 409 {
		t.Fatal("absent sequence accepted")
	}
	raw := []byte(`{"draft_revision":-1,"mode":"hybrid","groups":[],"policy":{}}`)
	w := httptest.NewRecorder()
	s.policyWorkflow(w, httptest.NewRequest("POST", "/api/v1/config/draft/policy", nil), raw, "id")
	if w.Code != 400 || s.draft != nil {
		t.Fatal("malformed revision accepted")
	}
}
func TestProxyURIImportDeduplicatesPrivatelyAndNeverApplies(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}
	s, _, _ := setup(t, runtime)
	in := ProxyImportRequest{URIs: []string{"trojan://first-private-secret@example.org:443#first", "trojan://first-private-secret@example.org:443#first", "trojan://second-private-secret@example.net:443#second"}}
	w := policyCall(s, "/api/v1/proxies/import", in)
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-secret") || len(s.draft.Model.Endpoints) != 3 || runtime.calls != 0 || runtime.checks != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result SubscriptionImportResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Imported != 2 {
		t.Fatal("stable node IDs not deduplicated")
	}
	nodes := s.draft.Model.Endpoints
	if nodes[1].ID > nodes[2].ID || !nodes[1].Enabled || !nodes[2].Enabled {
		t.Fatal("import order/enabled policy inconsistent")
	}
	in.DraftRevision = s.draft.Sequence
	w = policyCall(s, "/api/v1/proxies/import", in)
	if w.Code != 200 || len(s.draft.Model.Endpoints) != 3 {
		t.Fatal("repeat import duplicated endpoints")
	}
	before := s.draft.Sequence
	in.DraftRevision = before
	in.URIs = []string{"unsupported://private-input-secret@example.org"}
	w = policyCall(s, "/api/v1/proxies/import", in)
	if w.Code != 400 || s.draft.Sequence != before || strings.Contains(w.Body.String(), "private-input-secret") {
		t.Fatal("invalid URI saved or leaked")
	}
	in.URIs = make([]string, 129)
	if policyCall(s, "/api/v1/proxies/import", in).Code != 400 {
		t.Fatal("unbounded import")
	}
}

func TestPublicPolicyCanEditAgainAfterExactCommitAndRejectsExternalDrift(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 5, Ready: true}}
	s, _, token := setup(t, runtime)
	input := DraftPolicyRequest{Mode: runtime.m.Mode, Groups: runtime.m.Preview().Groups, Policy: policyPreview(runtime.m)}
	first := call(s, "POST", "/api/v1/config/draft/policy", token, input)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	planned := call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": s.draft.Sequence})
	planID := field(t, planned, "plan_id")
	applied := call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": planID})
	if applied.Code != 200 {
		t.Fatal(applied.Code, applied.Body.String())
	}
	if s.draft.BaseRevision != 5 || runtime.v.Revision != 6 {
		t.Fatal("commit changed audit record")
	}
	var get struct {
		Model  coreconfig.ModelPreview `json:"model"`
		Policy PolicyPreview           `json:"policy"`
	}
	response := call(s, "GET", "/api/v1/config", token, nil)
	json.Unmarshal(response.Body.Bytes(), &get)
	input = DraftPolicyRequest{DraftRevision: s.draft.Sequence, Mode: get.Model.Mode, Groups: get.Model.Groups, Policy: get.Policy}
	input.Policy.Rules = []coreconfig.Rule{{ID: "second-rule", Domains: []string{"example.net"}, Outbound: "direct"}}
	edited := call(s, "POST", "/api/v1/config/draft/policy", token, input)
	if edited.Code != 200 || strings.Contains(edited.Body.String(), "secret-password") || s.draft.BaseRevision != 6 {
		t.Fatal("public edit after commit failed", edited.Code, edited.Body.String())
	}
	planned = call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": s.draft.Sequence})
	planID = field(t, planned, "plan_id")
	applied = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": planID})
	if applied.Code != 200 || runtime.calls != 2 {
		t.Fatal("second plan/apply failed", applied.Code, applied.Body.String())
	}
	input.DraftRevision = s.draft.Sequence
	runtime.m.DNS.Bootstrap = "8.8.8.8"
	if call(s, "POST", "/api/v1/config/draft/policy", token, input).Code != 409 {
		t.Fatal("external model drift silently rebased")
	}
	runtime.m = s.draft.Model
	runtime.v.Revision++
	if call(s, "POST", "/api/v1/config/draft/policy", token, input).Code != 409 {
		t.Fatal("unrelated namespace revision silently rebased")
	}
}
