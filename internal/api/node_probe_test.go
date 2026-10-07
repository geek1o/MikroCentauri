package api

import (
	"context"
	"encoding/json"
	"errors"
	"mikrocentauri.local/core/internal/endpoints"
	"strings"
	"testing"
	"time"
)

type nodeProbeFixture struct {
	*fakeRuntime
	probeCalls int
	failure    error
}

func (n *nodeProbeFixture) ProbeNode(context.Context, string) (time.Duration, error) {
	n.probeCalls++
	return 25 * time.Millisecond, n.failure
}
func TestActiveNodeProbeContractsAndNoDraftCredentialTarget(t *testing.T) {
	runtime := &nodeProbeFixture{fakeRuntime: &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}}
	s, _, token := setup(t, runtime)
	path := "/api/v1/proxies/probe"
	input := NodeProbeRequest{ID: runtime.m.Endpoints[0].ID}
	raw, _ := json.Marshal(OpenAPI())
	var spec map[string]any
	json.Unmarshal(raw, &spec)
	w := call(s, "POST", path, token, input)
	contractResponse(t, spec, "POST", path, w)
	var result NodeProbeResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || !result.Success || result.LatencyMS != 25 || runtime.probeCalls != 1 || runtime.calls != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	runtime.failure = errors.New("raw-private-uri-password")
	w = call(s, "POST", path, token, input)
	json.Unmarshal(w.Body.Bytes(), &result)
	if result.Success || strings.Contains(w.Body.String(), "raw-private-uri") {
		t.Fatal(w.Body.String())
	}
	count := runtime.probeCalls
	if call(s, "POST", path, token, NodeProbeRequest{ID: strings.Repeat("f", 64)}).Code != 404 || runtime.probeCalls != count {
		t.Fatal("unknown/draft node probe")
	}
	extra, _ := endpoints.ParseURI("trojan://other-secret@other.example:443#other")
	runtime.m.Endpoints = append(runtime.m.Endpoints, extra)
	replaceEndpointReferences(&runtime.m, input.ID, extra.ID)
	runtime.m.Endpoints[0].Enabled = false
	if call(s, "POST", path, token, input).Code != 404 || runtime.probeCalls != count {
		t.Fatal("disabled node probed")
	}
	if call(s, "POST", path, token, map[string]any{"id": input.ID, "url": "https://arbitrary.invalid"}).Code != 400 || runtime.probeCalls != count {
		t.Fatal("arbitrary target accepted")
	}
	if call(s, "POST", path, "", input).Code != 401 || runtime.probeCalls != count {
		t.Fatal("unauthenticated probe")
	}
}
