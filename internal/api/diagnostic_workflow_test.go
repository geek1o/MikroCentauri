package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type diagnosticFixture struct {
	*fakeRuntime
	calls   int
	kind    string
	failure error
}

func (r *diagnosticFixture) Diagnose(ctx context.Context, kind string) error {
	r.calls++
	r.kind = kind
	return r.failure
}
func TestBoundedDiagnosticActionsDoNotApplyAndRedactFailures(t *testing.T) {
	runtime := &diagnosticFixture{fakeRuntime: &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}, failure: errors.New("private-operator-url credential-secret")}
	s, _, token := setup(t, runtime)
	raw, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(raw, &spec)
	for _, kind := range []string{"dns", "direct", "proxy", "routing", "watchdog"} {
		w := call(s, "POST", "/api/v1/diagnostics/run", token, DiagnosticRequest{Kind: kind})
		contractResponse(t, spec, "POST", "/api/v1/diagnostics/run", w)
		var result DiagnosticResult
		json.Unmarshal(w.Body.Bytes(), &result)
		if w.Code != 200 || result.Success || strings.Contains(w.Body.String(), "credential-secret") || runtime.kind != kind || result.Scope == "" || runtime.fakeRuntime.calls != 0 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	count := runtime.calls
	for _, in := range []any{map[string]any{"kind": "proxy", "url": "https://attacker.invalid/secret"}, DiagnosticRequest{Kind: "attacker"}} {
		if call(s, "POST", "/api/v1/diagnostics/run", token, in).Code != 400 || runtime.calls != count {
			t.Fatal("arbitrary diagnostic accepted")
		}
	}
	if call(s, "POST", "/api/v1/diagnostics/run", "", DiagnosticRequest{Kind: "proxy"}).Code != 401 || runtime.calls != count {
		t.Fatal("unauthenticated diagnostic")
	}
	runtime.failure = nil
	w := call(s, "POST", "/api/v1/diagnostics/run", token, DiagnosticRequest{Kind: "proxy"})
	var result DiagnosticResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.Success || result.Code != "proxy_verified" {
		t.Fatal(w.Body.String())
	}
}
func TestUnavailableDiagnosticAndOfflineCoreValidation(t *testing.T) {
	s, _, token := setup(t, nil)
	if call(s, "POST", "/api/v1/diagnostics/run", token, DiagnosticRequest{Kind: "dns"}).Code != 501 {
		t.Fatal("offline DNS fabricated")
	}
	if call(s, "POST", "/api/v1/diagnostics/run", token, DiagnosticRequest{Kind: "routeros"}).Code != 501 {
		t.Fatal("offline router fabricated")
	}
	w := call(s, "POST", "/api/v1/diagnostics/run", token, DiagnosticRequest{Kind: "core"})
	var result DiagnosticResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || !result.Success {
		t.Fatal(w.Code, w.Body.String())
	}
}
