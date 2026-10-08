package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/subscriptions"
)

type workflowManager struct {
	state     subscriptions.State
	refreshes int
	failure   error
}

func (m *workflowManager) Load(id string) (subscriptions.State, error) {
	v := m.state
	v.ID = id
	return v, nil
}
func (m *workflowManager) Refresh(ctx context.Context, s subscriptions.Spec) (subscriptions.State, error) {
	m.refreshes++
	state, _ := m.Load(s.ID)
	return state, m.failure
}
func workflowRegistry(t *testing.T) (*SubscriptionResources, *workflowManager, endpoints.Endpoint) {
	t.Helper()
	node, e := endpoints.ParseURI("trojan://subscription-secret@example.org:443#selected")
	if e != nil {
		t.Fatal(e)
	}
	manager := &workflowManager{state: subscriptions.State{Nodes: []endpoints.Endpoint{node}}}
	resources, e := NewSubscriptionResources(resourceDir(t), manager)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(resources.Close)
	if resources.Configure(subscriptions.Spec{ID: "provider", URL: "https://provider.example/subscription-private-token", Include: "selected"}) != nil {
		t.Fatal("configure")
	}
	return resources, manager, node
}
func workflowCall(s *Server, path string, input any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(input)
	r := httptest.NewRequest("POST", path, nil)
	w := httptest.NewRecorder()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.subscriptionWorkflow(w, r, raw, "request-fixture") {
		panic("unhandled route")
	}
	return w
}
func TestSubscriptionImportCredentialsStayPrivateAndDraftIsVersioned(t *testing.T) {
	registry, manager, node := workflowRegistry(t)
	s, _, _ := setup(t, nil)
	s.opts.Subscriptions = registry
	in := SubscriptionImportRequest{ID: "provider", NodeIDs: []string{node.ID}}
	w := workflowCall(s, "/api/v1/subscriptions/import", in)
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") || s.draft == nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if s.draft.Model.Endpoints[len(s.draft.Model.Endpoints)-1].Password != "subscription-secret" {
		t.Fatal("credentials not retained server-side")
	}
	if manager.refreshes != 0 {
		t.Fatal("import fetched network content")
	}
	before := s.draft.Sequence
	w = workflowCall(s, "/api/v1/subscriptions/import", in)
	if w.Code != 409 || s.draft.Sequence != before {
		t.Fatal("stale import changed draft")
	}
	in.DraftRevision = before
	w = workflowCall(s, "/api/v1/subscriptions/import", in)
	if w.Code != 200 || len(s.draft.Model.Endpoints) != len(s.opts.Model.Endpoints)+1 {
		t.Fatal("import not deduplicated", w.Body.String())
	}
	in.DraftRevision = s.draft.Sequence
	in.NodeIDs = []string{node.ID, node.ID}
	if workflowCall(s, "/api/v1/subscriptions/import", in).Code != 400 {
		t.Fatal("duplicate selection accepted")
	}
	in.NodeIDs = []string{"missing"}
	if workflowCall(s, "/api/v1/subscriptions/import", in).Code != 400 {
		t.Fatal("missing selection accepted")
	}
}
func TestSubscriptionImportValidatorFailureDoesNotSaveDraft(t *testing.T) {
	registry, _, node := workflowRegistry(t)
	s, _, _ := setup(t, nil)
	s.opts.Subscriptions = registry
	s.opts.Validate = func(context.Context, coreconfig.Model) error { return errors.New("private-engine-error") }
	w := workflowCall(s, "/api/v1/subscriptions/import", SubscriptionImportRequest{ID: "provider", NodeIDs: []string{node.ID}})
	if w.Code != 400 || s.draft != nil || strings.Contains(w.Body.String(), "private-engine-error") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestSubscriptionDeleteIsDurableAndMetadataRestorePreservesURL(t *testing.T) {
	registry, _, _ := workflowRegistry(t)
	dir := registry.dir
	metadata, e := registry.Metadata()
	raw, _ := json.Marshal(metadata)
	if e != nil || strings.Contains(string(raw), "private-token") || strings.Contains(string(raw), "https:") {
		t.Fatal(string(raw), e)
	}
	metadata[0].Include = "new.*"
	if registry.ValidateMetadata(metadata) != nil || registry.RestoreMetadata(metadata) != nil {
		t.Fatal("metadata restoration failed")
	}
	if registry.specs[0].URL != "https://provider.example/subscription-private-token" || registry.specs[0].Include != "new.*" {
		t.Fatal("metadata changed credentials")
	}
	if registry.ValidateMetadata([]SubscriptionMetadata{{ID: "unknown"}}) == nil {
		t.Fatal("unknown provider accepted")
	}
	if registry.ValidateMetadata([]SubscriptionMetadata{{ID: "provider", Include: "["}}) == nil {
		t.Fatal("invalid filter accepted")
	}
	if registry.Delete("provider") != nil {
		t.Fatal("delete failed")
	}
	registry.Close()
	reopened, e := NewSubscriptionResources(dir, &workflowManager{})
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	loaded, e := reopened.Metadata()
	if e != nil || len(loaded) != 0 {
		t.Fatal("deleted provider reappeared", e)
	}
}
func TestSubscriptionPeriodicRefreshBoundsAndCancellation(t *testing.T) {
	registry, manager, _ := workflowRegistry(t)
	if registry.Run(context.Background(), time.Second) == nil {
		t.Fatal("tight interval accepted")
	}
	if registry.Run(context.Background(), 25*time.Hour) == nil {
		t.Fatal("unbounded interval accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(registry.Run(ctx, time.Minute), context.Canceled) || manager.refreshes != 0 {
		t.Fatal("cancelled runner fetched or failed")
	}
}

func TestSubscriptionRefreshHistoryBoundedRedactedAndLKG(t *testing.T) {
	registry, manager, node := workflowRegistry(t)
	manager.failure = errors.New("https://provider.example/private-token subscription-secret")
	for i := 0; i < 140; i++ {
		result, e := registry.Refresh(context.Background(), "provider")
		if e == nil || len(result.Nodes) != 1 || result.Nodes[0].ID != node.ID {
			t.Fatal("failed refresh discarded LKG")
		}
	}
	events := registry.Events()
	raw, _ := json.Marshal(events)
	if len(events) != 128 || strings.Contains(string(raw), "private-token") || strings.Contains(string(raw), "secret") {
		t.Fatal("unbounded or unsafe history")
	}
	if events[len(events)-1].Event != "subscription_refresh_failed" || events[len(events)-1].Level != "warning" {
		t.Fatal("failed refresh absent")
	}
	events[0].Event = "tampered"
	if registry.Events()[0].Event == "tampered" {
		t.Fatal("mutable history exposed")
	}
}

type blockedRefreshManager struct{ started chan struct{} }

func (m *blockedRefreshManager) Load(id string) (subscriptions.State, error) {
	return subscriptions.State{ID: id}, nil
}
func (m *blockedRefreshManager) Refresh(ctx context.Context, s subscriptions.Spec) (subscriptions.State, error) {
	close(m.started)
	<-ctx.Done()
	return subscriptions.State{ID: s.ID}, ctx.Err()
}
func TestSubscriptionRefreshDoesNotHoldRegistryDuringDownload(t *testing.T) {
	manager := &blockedRefreshManager{started: make(chan struct{})}
	registry, e := NewSubscriptionResources(resourceDir(t), manager)
	if e != nil {
		t.Fatal(e)
	}
	defer registry.Close()
	spec := subscriptions.Spec{ID: "provider", URL: "https://provider.example/private-token"}
	if registry.Configure(spec) != nil {
		t.Fatal("configure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := registry.Refresh(ctx, spec.ID); done <- e }()
	select {
	case <-manager.started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	accessible := make(chan error, 1)
	go func() {
		_, e := registry.Metadata()
		if e == nil {
			e = registry.Delete(spec.ID)
		}
		accessible <- e
	}()
	select {
	case e := <-accessible:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("network refresh held registry mutex")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh ignored cancellation")
	}
}

func TestSubscriptionRegistryInvalidLoadReleasesExclusiveLock(t *testing.T) {
	dir := resourceDir(t)
	file := filepath.Join(dir, "subscription-specs.json")
	if e := os.WriteFile(file, []byte(`[{"id":"provider","url":"http://unsafe.example/secret"}]`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := NewSubscriptionResources(dir, &workflowManager{}); e == nil {
		t.Fatal("invalid durable specs accepted")
	}
	if e := os.WriteFile(file, []byte(`[]`), 0600); e != nil {
		t.Fatal(e)
	}
	registry, e := NewSubscriptionResources(dir, &workflowManager{})
	if e != nil {
		t.Fatal("failed load retained owner lock", e)
	}
	registry.Close()
}

func TestSubscriptionImportContinuesExactCommittedDraft(t *testing.T) {
	registry, _, node := workflowRegistry(t)
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Ready: true}}
	s, _, token := setup(t, runtime)
	s.opts.Subscriptions = registry
	saved := call(s, "POST", "/api/v1/config/draft/policy", token, DraftPolicyRequest{Mode: runtime.m.Mode, Groups: runtime.m.Preview().Groups, Policy: policyPreview(runtime.m)})
	if saved.Code != 200 {
		t.Fatal(saved.Code, saved.Body.String())
	}
	planned := call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": s.draft.Sequence})
	id := field(t, planned, "plan_id")
	applied := call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id})
	if applied.Code != 200 {
		t.Fatal(applied.Code, applied.Body.String())
	}
	imported := call(s, "POST", "/api/v1/subscriptions/import", token, SubscriptionImportRequest{ID: "provider", NodeIDs: []string{node.ID}, DraftRevision: s.draft.Sequence})
	if imported.Code != 200 || s.draft.BaseRevision != runtime.v.Revision || len(s.draft.Model.Endpoints) != 2 || runtime.calls != 1 || strings.Contains(imported.Body.String(), "subscription-secret") {
		t.Fatal("postcommit subscription import failed", imported.Code, imported.Body.String())
	}
}

func TestSubscriptionImportCreatesSelectorAtomically(t *testing.T) {
	registry, _, node := workflowRegistry(t)
	s, _, _ := setup(t, nil)
	s.opts.Subscriptions = registry
	in := SubscriptionImportRequest{ID: "provider", NodeIDs: []string{node.ID}, SelectorID: "subscription-selector"}
	w := workflowCall(s, "/api/v1/subscriptions/import", in)
	if w.Code != 200 || s.draft == nil {
		t.Fatal(w.Code, w.Body.String())
	}
	found := false
	for _, g := range s.draft.Model.Groups {
		if g.ID == in.SelectorID {
			found = g.Type == "selector" && g.Selected == node.ID && len(g.Members) == 1 && g.Members[0] == node.ID
		}
	}
	if !found {
		t.Fatal("import did not create the requested selector")
	}
	before, _ := json.Marshal(s.draft)
	in.DraftRevision = s.draft.Sequence
	in.SelectorID = "invalid selector"
	w = workflowCall(s, "/api/v1/subscriptions/import", in)
	after, _ := json.Marshal(s.draft)
	if w.Code != 400 || string(before) != string(after) {
		t.Fatal("invalid selector partially changed the draft", w.Code)
	}
}
