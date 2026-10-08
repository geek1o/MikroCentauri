package api

import (
	"crypto/x509"
	"fmt"
	"mikrocentauri.local/core/internal/subscriptions"
	"mikrocentauri.local/core/internal/trafficlists"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func listSourceFixture(t *testing.T, s *Server, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	manager, e := trafficlists.New(filepath.Join(dir, "lists"), subscriptions.Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	s.opts.TrafficLists = manager
	return srv
}
func TestDownloadedListsSaveReviewablePolicyWithoutApplying(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, runtime)
	body := "site.example\n*.video.example\n"
	requests := 0
	source := listSourceFixture(t, s, func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, body) })
	input := TrafficListRequest{Outbound: runtime.m.Groups[0].ID, Custom: &trafficlists.Spec{ID: "streaming", Name: "Streaming", URL: source.URL + "/private-source-token"}}
	w := call(s, "POST", "/api/v1/traffic-lists/import", token, input)
	if w.Code != 200 || s.draft == nil || runtime.calls != 0 || runtime.checks != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	rule := s.draft.Model.Rules[len(s.draft.Model.Rules)-1]
	if rule.ID != "list-streaming" || len(rule.Suffixes) != 2 || rule.Outbound != input.Outbound {
		t.Fatal("wrong downloaded route")
	}
	views := call(s, "GET", "/api/v1/traffic-lists", token, nil)
	if views.Code != 200 || strings.Contains(views.Body.String(), "private-source-token") || strings.Contains(views.Body.String(), source.URL) {
		t.Fatal("source URL leak")
	}
	if call(s, "POST", "/api/v1/traffic-lists/import", token, input).Code != 409 || requests != 1 {
		t.Fatal("stale import fetched source")
	}
	previous := s.draft.Sequence
	body = "malformed body"
	input = TrafficListRequest{DraftRevision: previous, IDs: []string{"streaming"}, Outbound: input.Outbound}
	if call(s, "POST", "/api/v1/traffic-lists/import", token, input).Code != 422 || s.draft.Sequence != previous {
		t.Fatal("invalid refresh mutated draft")
	}
	snapshot, e := s.opts.TrafficLists.Load("streaming")
	if e != nil || len(snapshot.Domains) != 2 {
		t.Fatal("last good snapshot lost")
	}
}
func TestListDownloadDoesNotBlockHealthAndRejectsConcurrentDraft(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, runtime)
	started := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	source := listSourceFixture(t, s, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, "site.example\n")
	})
	input := TrafficListRequest{Outbound: runtime.m.Groups[0].ID, Custom: &trafficlists.Spec{ID: "custom", Name: "Custom", URL: source.URL}}
	result := make(chan int, 1)
	go func() { result <- call(s, "POST", "/api/v1/traffic-lists/import", token, input).Code }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not start")
	}
	health := make(chan int, 1)
	go func() { health <- call(s, "GET", "/api/v1/health/ready", token, nil).Code }()
	select {
	case code := <-health:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("download stalled readiness")
	}
	in := DraftPolicyRequest{Mode: runtime.m.Mode, Groups: runtime.m.Groups, Policy: policyPreview(runtime.m)}
	if call(s, "POST", "/api/v1/config/draft/policy", token, in).Code != 200 {
		t.Fatal("concurrent draft failed")
	}
	seq := s.draft.Sequence
	close(release)
	released = true
	if code := <-result; code != 409 || s.draft.Sequence != seq {
		t.Fatal("stale download overwrote newer draft", code)
	}

}

func TestNetworkSnapshotCreatesDestinationPolicyWithoutDNSAdmission(t *testing.T) {
	s, _, _ := setup(t, nil)
	m, e := s.model()
	if e != nil {
		t.Fatal(e)
	}
	before := strings.Join(m.DNS.SelectedDomains, ",")
	snapshot := trafficlists.Snapshot{Spec: trafficlists.Spec{ID: "cdn-ip", Name: "CDN", Kind: "networks"}, Prefixes: []string{"1.1.1.0/24", "8.8.8.0/24"}}
	result, e := installListSnapshots(m, "proxy", []trafficlists.Snapshot{snapshot})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(result.DNS.SelectedDomains, ",") != before {
		t.Fatal("network import polluted DNS namespace")
	}
	found := false
	for _, r := range result.Rules {
		if r.ID == "list-cdn-ip" {
			found = len(r.DestinationCIDRs) == 2 && len(r.Suffixes) == 0 && r.Outbound == "proxy"
		}
	}
	if !found {
		t.Fatal("network list did not create destination policy")
	}
}
