package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/subscriptions"
)

func TestSubscriptionProxySelectionUsesDraftAndPersistsWithoutURLDisclosure(t *testing.T) {
	var hits atomic.Int32
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("trojan://source-private-password@example.com:443#imported"))
	}))
	defer source.Close()
	roots := x509.NewCertPool()
	roots.AddCert(source.Certificate())
	m, err := subscriptions.New(resourceDir(t), subscriptions.Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSubscriptionResources(resourceDir(t), m)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if registry.Configure(subscriptions.Spec{ID: "source", URL: source.URL + "/private-url-token"}) != nil {
		t.Fatal("configure")
	}
	s, _, token := setup(t, nil)
	node, _ := endpoints.ParseURI("trojan://draft-private-password@example.net:443#download-only")
	calls := 0
	s.opts.Subscriptions = registry
	// This runner is a composition stub; the real child/tunnel is tested separately.
	s.opts.SubscriptionProxy = func(ctx context.Context, ep endpoints.Endpoint, bootstrap string, operation func(context.Context, subscriptions.DialContext) error) error {
		calls++
		if ep.ID != node.ID || bootstrap != "1.1.1.1" {
			t.Error("wrong endpoint snapshot")
		}
		return operation(ctx, (&net.Dialer{}).DialContext)
	}
	s, err = New(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	model, _ := s.model()
	model.Endpoints = append(model.Endpoints, node)
	if s.saveDraft(model) != nil {
		t.Fatal("draft")
	}
	revision := s.draft.Sequence
	w := call(s, "POST", "/api/v1/subscriptions/transport", token, SubscriptionTransportRequest{ID: "source", ProxyNode: node.ID})
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = call(s, "POST", "/api/v1/subscriptions/refresh", token, map[string]string{"id": "source"})
	if w.Code != 200 || calls != 1 || hits.Load() != 1 || s.draft.Sequence != revision || s.opts.Runtime != nil {
		t.Fatal("draft fetch applied state or failed", w.Code, w.Body.String(), calls)
	}
	if registry.specs[0].URL != source.URL+"/private-url-token" {
		t.Fatal("transport replaced secret URL")
	}
	metadata, err := registry.Metadata()
	raw, _ := json.Marshal(metadata)
	if err != nil || metadata[0].ProxyNode != node.ID || strings.Contains(string(raw), "private-url-token") {
		t.Fatal("transport metadata leak or loss")
	}
	model.Endpoints[len(model.Endpoints)-1].Enabled = false
	if s.saveDraft(model) != nil {
		t.Fatal("disable draft node")
	}
	w = call(s, "POST", "/api/v1/subscriptions/refresh", token, map[string]string{"id": "source"})
	if w.Code != 503 || calls != 1 || hits.Load() != 1 || !strings.Contains(w.Body.String(), "proxy_unavailable") {
		t.Fatal("disabled draft node bypassed proxy selection", w.Code, w.Body.String())
	}
	state, _ := m.Load("source")
	if len(state.Nodes) != 1 {
		t.Fatal("unavailable proxy lost last-good nodes")
	}
	before := registry.specs[0]
	if call(s, "POST", "/api/v1/subscriptions/transport", token, SubscriptionTransportRequest{ID: "source", ProxyNode: "https://user:private@proxy.example"}).Code != 400 || registry.specs[0] != before {
		t.Fatal("arbitrary proxy URL accepted")
	}
}

func TestProxySourceStartupDoesNotHoldAPIMutex(t *testing.T) {
	m, err := subscriptions.New(resourceDir(t), subscriptions.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSubscriptionResources(resourceDir(t), m)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	s, _, token := setup(t, nil)
	node := s.opts.Model.Endpoints[0]
	registry.Configure(subscriptions.Spec{ID: "source", URL: "https://example.com/private-url-token", ProxyNode: node.ID})
	started := make(chan struct{})
	release := make(chan struct{})
	s.opts.Subscriptions = registry
	s.opts.SubscriptionProxy = func(ctx context.Context, _ endpoints.Endpoint, _ string, _ func(context.Context, subscriptions.DialContext) error) error {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return context.Canceled
	}
	s, err = New(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- call(s, "POST", "/api/v1/subscriptions/refresh", token, map[string]string{"id": "source"})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("proxy startup not reached")
	}
	health := make(chan int, 1)
	go func() { health <- call(s, "GET", "/api/v1/system", token, nil).Code }()
	select {
	case code := <-health:
		if code != 200 {
			t.Error("liveness failed", code)
		}
	case <-time.After(time.Second):
		t.Error("proxy source held API mutex")
	}
	close(release)
	select {
	case response := <-done:
		if response.Code != 503 {
			t.Fatal("startup failure accepted", response.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy source did not finish")
	}
}

func TestSubscriptionProxyCanReuseAnExactlyCommittedDraft(t *testing.T) {
	m := fixture(t)
	active, _ := m.Clone()
	rt := &fakeRuntime{m: active, v: RuntimeView{Revision: 7}}
	s, _, _ := setup(t, rt)
	if s.saveDraft(m) != nil {
		t.Fatal("draft")
	}
	rt.v.Revision = 8 // Successful apply retains this exact draft as its audit record.
	calls := 0
	s.opts.SubscriptionProxy = func(context.Context, endpoints.Endpoint, string, func(context.Context, subscriptions.DialContext) error) error {
		calls++
		return nil
	}
	operation := func(context.Context, subscriptions.DialContext) error { return nil }
	if err := s.withSubscriptionProxy(context.Background(), m.Endpoints[0].ID, operation); err != nil || calls != 1 {
		t.Fatal("committed draft blocked source refresh", err)
	}
	rt.m.Endpoints[0].Name = "a different private active model"
	if err := s.withSubscriptionProxy(context.Background(), m.Endpoints[0].ID, operation); err == nil || calls != 1 {
		t.Fatal("stale draft started a proxy")
	}
}

type scheduledProxyManager struct {
	direct, via atomic.Int32
	selected    string
}

func (m *scheduledProxyManager) Load(id string) (subscriptions.State, error) {
	return subscriptions.State{ID: id}, nil
}
func (m *scheduledProxyManager) Refresh(context.Context, subscriptions.Spec) (subscriptions.State, error) {
	m.direct.Add(1)
	return subscriptions.State{}, nil
}
func (m *scheduledProxyManager) RefreshVia(_ context.Context, spec subscriptions.Spec, _ subscriptions.DialContext) (subscriptions.State, error) {
	m.via.Add(1)
	m.selected = spec.ProxyNode
	return subscriptions.State{ID: spec.ID}, nil
}

func TestUnattendedSubscriptionUsesTheSavedProxyPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := &scheduledProxyManager{}
		registry, err := NewSubscriptionResources(resourceDir(t), m)
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		nodeID := strings.Repeat("a", 64)
		if registry.Configure(subscriptions.Spec{ID: "source", URL: "https://example.com/private-token", ProxyNode: nodeID}) != nil {
			t.Fatal("configure")
		}
		registry.proxy = func(ctx context.Context, _ string, operation func(context.Context, subscriptions.DialContext) error) error {
			return operation(ctx, func(context.Context, string, string) (net.Conn, error) { return nil, context.Canceled })
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- registry.RunScheduled(ctx) }()
		synctest.Wait()
		if _, err := registry.SetSchedule(60); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if m.via.Load() != 0 || m.direct.Load() != 0 {
			t.Fatal("schedule fetched immediately")
		}
		time.Sleep(61 * time.Second)
		synctest.Wait()
		cancel()
		<-done
		if m.via.Load() != 1 || m.direct.Load() != 0 || m.selected != nodeID {
			t.Fatal("schedule bypassed saved proxy", m.via.Load(), m.direct.Load())
		}
	})
}
