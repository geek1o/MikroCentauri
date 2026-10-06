package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
)

func fixture(t *testing.T) coreconfig.Model {
	t.Helper()
	ep, e := endpoints.ParseURI("ss://YWVzLTEyOC1nY206c2VjcmV0LXBhc3N3b3Jk@127.0.0.1:9000#test")
	if e != nil {
		t.Fatal(e)
	}
	return coreconfig.Model{SchemaVersion: 2, Instance: "api-test", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{ep.ID}, Selected: ep.ID}}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/api-test/cache.db"}}
}

type fakeRuntime struct {
	m             coreconfig.Model
	v             RuntimeView
	calls, checks int
	failure       bool
}

func (f *fakeRuntime) View() RuntimeView                { return f.v }
func (f *fakeRuntime) Model() (coreconfig.Model, error) { return f.m.Clone() }
func (f *fakeRuntime) Validate(_ context.Context, rev uint64, m coreconfig.Model) error {
	f.checks++
	if rev != f.v.Revision {
		return errors.New("private validation secret")
	}
	return m.Validate()
}
func (f *fakeRuntime) Apply(_ context.Context, rev uint64, m coreconfig.Model) error {
	f.calls++
	if f.failure {
		f.v.Pending = true
		f.v.Ready = false
		return errors.New("secret from runtime")
	}
	if rev != f.v.Revision {
		return errors.New("stale")
	}
	f.v.Revision++
	f.m = m
	return nil
}
func setup(t *testing.T, r Runtime) (*Server, *Auth, string) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	if e := InitializeAuth(dir, []byte("correct-password-for-api")); e != nil {
		t.Fatal(e)
	}
	a, e := OpenAuth(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(a.Close)
	s, e := New(Options{Directory: dir, Auth: a, Model: fixture(t), Runtime: r, Origin: "https://127.0.0.1:8443", Validate: func(_ context.Context, m coreconfig.Model) error { return m.Validate() }})
	if e != nil {
		t.Fatal(e)
	}
	token, status := a.Login("correct-password-for-api")
	if status != 200 {
		t.Fatal(status)
	}
	return s, a, token
}
func call(s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	var raw []byte
	switch v := body.(type) {
	case string:
		raw = []byte(v)
	default:
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "https://127.0.0.1:8443"+path, bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func field(t *testing.T, w *httptest.ResponseRecorder, key string) any {
	t.Helper()
	var v map[string]any
	if json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal(w.Body.String())
	}
	return v[key]
}
func TestAPICandidateCASAndSingleOwner(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, rt)
	if w := call(s, "POST", "/api/v1/config/draft", token, rt.m); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if rt.calls != 0 {
		t.Fatal("draft activated")
	}
	input := map[string]any{"draft_revision": 1}
	w := call(s, "POST", "/api/v1/config/plan", token, input)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	id := field(t, w, "plan_id")
	rt.v.Revision = 8
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id}); w.Code != 409 || rt.calls != 0 {
		t.Fatal("stale plan applied")
	}
	call(s, "POST", "/api/v1/config/draft", token, rt.m)
	w = call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 2})
	id = field(t, w, "plan_id")
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id}); w.Code != 200 || rt.calls != 1 || rt.v.Revision != 9 {
		t.Fatal(w.Body.String())
	}
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id}); w.Code != 409 || rt.calls != 1 {
		t.Fatal("plan replay")
	}
}
func TestFailedApplyIsConsumedAndPendingIsNotReady(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 1, Ready: true}, failure: true}
	s, _, token := setup(t, rt)
	call(s, "POST", "/api/v1/config/draft", token, rt.m)
	w := call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 1})
	id := field(t, w, "plan_id")
	w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id})
	if w.Code != 503 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal(w.Body.String())
	}
	if w = call(s, "GET", "/api/v1/health/ready", token, nil); w.Code != 503 {
		t.Fatal("pending healthy")
	}
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id}); w.Code != 409 || rt.calls != 1 {
		t.Fatal("failed plan replay")
	}
}
func TestExportDiagnosticsAndLogsExcludeCredentials(t *testing.T) {
	s, _, token := setup(t, nil)
	for _, path := range []string{"config", "proxies", "groups", "rules", "devices", "dns", "diagnostics", "backup", "logs"} {
		w := call(s, "GET", "/api/v1/"+path, token, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "secret-password") {
			t.Fatal(path, w.Body.String())
		}
	}
	backup := Export(fixture(t))
	w := call(s, "POST", "/api/v1/backup/restore-preview", token, backup)
	if w.Code != 200 || field(t, w, "apply_performed") != false {
		t.Fatal(w.Body.String())
	}
	backup.Schema = SafeBackupSchema + 1
	if w = call(s, "POST", "/api/v1/backup/restore-preview", token, backup); w.Code != 422 {
		t.Fatal("future backup accepted")
	}
}
func TestTLSOriginClientAndAuthRejections(t *testing.T) {
	s, _, token := setup(t, nil)
	for _, change := range []func(*http.Request){func(r *http.Request) { r.TLS = nil }, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example") }, func(r *http.Request) { r.Host = "attacker.example" }, func(r *http.Request) {
		r.RemoteAddr = "203.0.113.10:1000"
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
	}, func(r *http.Request) { r.URL.RawQuery = "access_token=" + token }} {
		r := httptest.NewRequest("GET", "https://127.0.0.1:8443/api/v1/config", nil)
		r.RemoteAddr = "127.0.0.1:1000"
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+token)
		change(r)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := call(s, "GET", "/api/v1/config", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestAuthExpiryRateLimitAndRestart(t *testing.T) {
	_, a, token := setup(t, nil)
	now := time.Now()
	a.now = func() time.Time { return now }
	now = now.Add(31 * time.Minute)
	if a.Valid(token) {
		t.Fatal("expired token accepted")
	}
	for range 5 {
		if _, code := a.Login("wrong"); code != 401 {
			t.Fatal(code)
		}
	}
	if _, code := a.Login("correct-password-for-api"); code != 429 {
		t.Fatal("limit bypass")
	}
	now = now.Add(time.Minute)
	if _, code := a.Login("correct-password-for-api"); code != 200 {
		t.Fatal(code)
	}
}
func TestDraftReopenPermissionsAndSafeOfflineApply(t *testing.T) {
	s, a, token := setup(t, nil)
	w := call(s, "POST", "/api/v1/config/draft", token, fixture(t))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	fi, e := os.Stat(filepath.Join(s.dir, "draft.json"))
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("public draft")
	}
	a.Close()
	next, e := OpenAuth(s.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.Valid(token) {
		t.Fatal("session survives restart")
	}
	reopened, e := New(Options{Directory: s.dir, Auth: next, Model: fixture(t), Origin: s.opts.Origin, Validate: s.opts.Validate})
	if e != nil || reopened.draft.Sequence != 1 {
		t.Fatal("draft lost", e)
	}
	newToken, _ := next.Login("correct-password-for-api")
	w = call(reopened, "POST", "/api/v1/config/plan", newToken, map[string]any{"draft_revision": 1})
	id := field(t, w, "plan_id")
	if w = call(reopened, "POST", "/api/v1/config/apply", newToken, map[string]any{"plan_id": id}); w.Code != 503 || field(t, w, "error") != "runtime_not_connected" {
		t.Fatal(w.Body.String())
	}
}
func TestAmbiguousOversizedAndExpiredPlans(t *testing.T) {
	s, _, token := setup(t, nil)
	for _, raw := range []string{`{"draft_revision":1,"draft_revision":2}`, `{"draft_revision":1} {}`, `{"unexpected":1}`, strings.Repeat("x", (4<<20)+1)} {
		if w := call(s, "POST", "/api/v1/config/plan", token, raw); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	call(s, "POST", "/api/v1/config/draft", token, fixture(t))
	w := call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 1})
	id := field(t, w, "plan_id")
	s.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": id}); w.Code != 409 {
		t.Fatal("expired plan accepted")
	}
}
func TestPrivateStateRejectsSymlinksAndSecondOwner(t *testing.T) {
	s, _, _ := setup(t, nil)
	if a, e := OpenAuth(s.dir); e == nil {
		a.Close()
		t.Fatal("second owner")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	os.Symlink(s.dir, link)
	if _, e := PrivateDirectory(link); e == nil {
		t.Fatal("symlink accepted")
	}
	p := filepath.Join(parent, "public")
	os.Mkdir(p, 0755)
	if _, e := PrivateDirectory(p); e == nil {
		t.Fatal("public directory accepted")
	}
}
func TestOpenAPIRouteGroupsAndModelSchema(t *testing.T) {
	spec := OpenAPI()
	paths := spec["paths"].(map[string]any)
	for _, p := range []string{"system", "routeros", "subscriptions", "config/apply", "backup/restore-preview", "auth/login", "health/ready"} {
		if paths["/api/v1/"+p] == nil {
			t.Fatal(p)
		}
	}
	model := spec["components"].(map[string]any)["schemas"].(map[string]any)["CoreModel"].(map[string]any)
	if model["additionalProperties"] != false {
		t.Fatal("schema accepts unknown fields")
	}
}

func TestActualTLSLoginAndAuthenticatedHTTP(t *testing.T) {
	s, _, _ := setup(t, nil)
	server := httptest.NewUnstartedServer(s)
	s.opts.Origin = "https://" + server.Listener.Addr().String()
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	resp, e := client.Post(server.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"password":"correct-password-for-api"}`))
	if e != nil {
		t.Fatal(e)
	}
	var login map[string]any
	e = json.NewDecoder(resp.Body).Decode(&login)
	resp.Body.Close()
	if e != nil || resp.StatusCode != 200 {
		t.Fatal("real TLS login", e, resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", server.URL+"/api/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+login["access_token"].(string))
	resp, e = client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS.Version != tls.VersionTLS13 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("real TLS API", resp.StatusCode)
	}
}

func TestDraftPersistenceErrorRequiresReopen(t *testing.T) {
	s, _, token := setup(t, nil)
	path := filepath.Join(s.dir, "draft.json")
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if w := call(s, "POST", "/api/v1/config/draft", token, fixture(t)); w.Code != 503 {
		t.Fatal(w.Body.String())
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if w := call(s, "POST", "/api/v1/config/draft", token, fixture(t)); w.Code != 503 || field(t, w, "error") != "persistence_requires_reopen" {
		t.Fatal("ambiguous persistence reused", w.Body.String())
	}
}
func TestPublishedOpenAPIEqualsGeneratedContract(t *testing.T) {
	raw, e := os.ReadFile("../../docs/api/openapi.json")
	if e != nil {
		t.Fatal(e)
	}
	generated, e := json.MarshalIndent(OpenAPI(), "", "  ")
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), generated) {
		t.Fatal("regenerate OpenAPI with api-openapi")
	}
}
