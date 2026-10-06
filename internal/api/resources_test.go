package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/subscriptions"
)

func resourceDir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0700)
	return p
}
func TestRealRouterOSTLSReadOnlyResourceProjection(t *testing.T) {
	var reads atomic.Int32
	var mutations atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutations.Add(1)
			w.WriteHeader(403)
			return
		}
		reads.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "api-fixture" || password != "router-password-secret" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/rest/system/resource":
			json.NewEncoder(w).Encode(map[string]string{"version": "7.24.5 (stable)", "architecture-name": "x86_64", "board-name": "CHR x86_64", "platform": "MikroTik"})
		case "/rest/system/package":
			json.NewEncoder(w).Encode([]map[string]string{{"name": "routeros", "version": "7.24.5", "disabled": "false"}})
		case "/rest/interface":
			json.NewEncoder(w).Encode([]map[string]string{{"name": "ether1", "type": "ether", "disabled": "false", "running": "true"}})
		case "/rest/ip/route":
			json.NewEncoder(w).Encode([]map[string]string{{".id": "*1", "comment": "mikrocentauri:api-test:route:fakeip", "disabled": "true", "gateway": "DO-NOT-EXPOSE-RAW-ROUTER-ROW"}, {".id": "*2", "comment": "foreign-router-password-secret", "disabled": "false"}})
		default:
			w.Write([]byte(`[]`))
		}
	}))
	defer remote.Close()
	client, e := routeros.NewClient(remote.URL+"/rest", "api-fixture", "router-password-secret", remote.Client())
	if e != nil {
		t.Fatal(e)
	}
	s, _, token := setup(t, nil)
	s.opts.Router = &RouterResources{Client: client, Instance: "api-test"}
	w := call(s, "GET", "/api/v1/routeros", token, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "DO-NOT-EXPOSE") {
		t.Fatal(w.Code, w.Body.String())
	}
	var result RouterSnapshot
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.OwnedCounts["ip/route"] != 1 || result.OwnedDisabled["ip/route"] != 1 || result.Capabilities.Version != "7.24.5 (stable)" {
		t.Fatal(w.Body.String())
	}
	if reads.Load() == 0 || mutations.Load() != 0 {
		t.Fatal("resource mutated router")
	}
}
func TestHTTPSSubscriptionResourceRefreshLKGAndPrivateReopen(t *testing.T) {
	var body atomic.Value
	body.Store("trojan://proxy-secret@example.com:443#first")
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body.Load().(string))) }))
	defer remote.Close()
	roots := x509.NewCertPool()
	roots.AddCert(remote.Certificate())
	manager, e := subscriptions.New(resourceDir(t), subscriptions.Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, RootCAs: roots})
	if e != nil {
		t.Fatal(e)
	}
	dir := resourceDir(t)
	providers, e := NewSubscriptionResources(dir, manager)
	if e != nil {
		t.Fatal(e)
	}
	defer providers.Close()
	s, _, token := setup(t, nil)
	s.opts.Subscriptions = providers
	spec := subscriptions.Spec{ID: "provider", URL: remote.URL + "/subscription?credential=subscription-secret"}
	w := call(s, "POST", "/api/v1/subscriptions", token, spec)
	if w.Code != 200 || strings.Contains(w.Body.String(), "subscription-secret") {
		t.Fatal(w.Body.String())
	}
	w = call(s, "POST", "/api/v1/subscriptions/refresh", token, map[string]string{"id": "provider"})
	if w.Code != 200 || strings.Contains(w.Body.String(), "proxy-secret") {
		t.Fatal(w.Body.String())
	}
	first, _ := manager.Load("provider")
	body.Store("invalid proxy-secret")
	w = call(s, "POST", "/api/v1/subscriptions/refresh", token, map[string]string{"id": "provider"})
	if w.Code != 503 || strings.Contains(w.Body.String(), "proxy-secret") || strings.Contains(w.Body.String(), "subscription-secret") {
		t.Fatal(w.Body.String())
	}
	after, _ := manager.Load("provider")
	if len(after.Nodes) != 1 || after.Nodes[0].ID != first.Nodes[0].ID || after.LastSuccess != first.LastSuccess || after.Failure == "" {
		t.Fatal("LKG lost")
	}
	for _, path := range []string{"subscriptions", "logs", "diagnostics"} {
		w = call(s, "GET", "/api/v1/"+path, token, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "proxy-secret") || strings.Contains(w.Body.String(), "subscription-secret") {
			t.Fatal(path, w.Body.String())
		}
	}
	fi, e := os.Stat(filepath.Join(dir, "subscription-specs.json"))
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("private subscription URL exposed")
	}
	if second, e := NewSubscriptionResources(dir, manager); e == nil {
		second.Close()
		t.Fatal("second registry owner")
	}
	providers.Close()
	reopened, e := NewSubscriptionResources(dir, manager)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	rows, e := reopened.List()
	if e != nil || len(rows) != 1 || len(rows[0].Nodes) != 1 || !rows[0].Failed {
		t.Fatal("state not restored", e)
	}
}
func TestSubscriptionDefaultsRefuseSSRFAndUntrustedTLS(t *testing.T) {
	var requests atomic.Int32
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("trojan://private-secret@example.com:443"))
	}))
	defer remote.Close()
	for _, policy := range []subscriptions.Policy{{}, {AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}} {
		manager, e := subscriptions.New(resourceDir(t), policy)
		if e != nil {
			t.Fatal(e)
		}
		providers, e := NewSubscriptionResources(resourceDir(t), manager)
		if e != nil {
			t.Fatal(e)
		}
		spec := subscriptions.Spec{ID: "provider", URL: remote.URL}
		if e = providers.Configure(spec); e != nil {
			t.Fatal(e)
		}
		if _, e = providers.Refresh(context.Background(), "provider"); e == nil {
			t.Fatal("SSRF or untrusted TLS accepted")
		}
		providers.Close()
	}
	if requests.Load() != 0 {
		t.Fatal("unsafe provider was queried")
	}
	for _, url := range []string{"http://example.com/sub", "https://secret:password@example.com/sub", "https://example.com/sub#secret"} {
		if validateSpec(subscriptions.Spec{ID: "provider", URL: url}) == nil {
			t.Fatal("unsafe spec", url)
		}
	}
}
func TestAuthenticatedHostRecoveryAndApply(t *testing.T) {
	h, owner, _ := newTestHost(t)
	s, _, token := setup(t, h)
	w := call(s, "POST", "/api/v1/system/recover", token, map[string]any{})
	if w.Code != 200 || !h.View().Ready {
		t.Fatal(w.Body.String())
	}
	w = call(s, "POST", "/api/v1/config/draft", token, owner.m)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 1})
	id := field(t, w, "plan_id")
	w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id})
	if w.Code != 200 || h.View().Revision != 2 || !h.View().Ready {
		t.Fatal(w.Body.String())
	}
}

func TestSubscriptionInspectionIsBounded(t *testing.T) {
	state := subscriptions.State{ID: "provider", Nodes: make([]endpoints.Endpoint, 130), ImportedCount: 130}
	node := fixture(t).Endpoints[0]
	for i := range state.Nodes {
		state.Nodes[i] = node
	}
	first := subscriptionPreview(state)
	last := subscriptionPage(state, 128, 128)
	if len(first.Nodes) != 128 || !first.HasMore || first.NodeCount != 130 || len(last.Nodes) != 2 || last.HasMore || last.Offset != 128 {
		t.Fatal("unbounded or truncated without metadata")
	}
}
func TestDiagnosticsBundleHasFixedPrivateNamesAndNoCredentials(t *testing.T) {
	s, _, token := setup(t, nil)
	w := call(s, "GET", "/api/v1/diagnostics/bundle", token, nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/gzip" {
		t.Fatal(w.Code, w.Body.String())
	}
	gz, e := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	count := 0
	for {
		header, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		count++
		if header.Mode != 0600 || strings.Contains(header.Name, "/") {
			t.Fatal("unsafe bundle name or mode")
		}
		raw, e := io.ReadAll(reader)
		if e != nil || strings.Contains(string(raw), "secret-password") || strings.Contains(string(raw), "\"password\"") {
			t.Fatal("credentials in bundle", string(raw))
		}
	}
	if count != 3 {
		t.Fatal(count)
	}
}

type reviewedRuntime struct {
	*fakeRuntime
	source string
}

func (r *reviewedRuntime) CandidateFingerprint(context.Context, uint64, coreconfig.Model) (string, error) {
	return r.source, nil
}
func (r *reviewedRuntime) ApplyPrepared(ctx context.Context, rev uint64, m coreconfig.Model, source string) error {
	if source != r.source {
		return coreactivation.ErrCandidateChanged
	}
	return r.fakeRuntime.Apply(ctx, rev, m)
}
func TestAPIChangedArtifactPlanIsConflictWithoutApply(t *testing.T) {
	rt := &reviewedRuntime{fakeRuntime: &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 3, Ready: true}}, source: strings.Repeat("1", 64)}
	s, _, token := setup(t, rt)
	call(s, "POST", "/api/v1/config/draft", token, rt.m)
	w := call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 1})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	id := field(t, w, "plan_id")
	rt.source = strings.Repeat("2", 64)
	w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id})
	if w.Code != 409 || field(t, w, "error") != "candidate_changed" || rt.calls != 0 || !rt.View().Ready {
		t.Fatal(w.Body.String())
	}
}

func TestReviewPolicyExcludesRemoteURLsAndCachePaths(t *testing.T) {
	s, _, token := setup(t, nil)
	m := fixture(t)
	m.RuleSets = []rulesets.Spec{{ID: "private-list", Format: "source", URL: "https://provider.example/private-subscription-secret"}}
	m.Rules = []coreconfig.Rule{{ID: "private-rule", RuleSets: []string{"private-list"}, Outbound: "direct"}}
	s.opts.Model = m
	for _, path := range []string{"config", "config/draft"} {
		if path == "config/draft" {
			if w := call(s, "POST", "/api/v1/config/draft", token, m); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
		}
		w := call(s, "GET", "/api/v1/"+path, token, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-subscription-secret") || strings.Contains(w.Body.String(), m.DNS.CachePath) || strings.Contains(w.Body.String(), "secret-password") {
			t.Fatal(w.Body.String())
		}
		var value map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &value) != nil || !strings.Contains(string(value["policy"]), "private-rule") {
			t.Fatal("rules not reviewable", w.Body.String())
		}
	}
}
