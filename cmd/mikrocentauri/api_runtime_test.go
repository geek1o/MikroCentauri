package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
)

func TestAPIListenerAndArgumentsRejectBeforeInitialization(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8443", "8.8.8.8:8443", "localhost:8443", "[::]:8443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:nope"} {
		t.Run(listen, func(t *testing.T) {
			e := apiCommand("api-serve", []string{"-state", "/unused", "-listen", listen})
			if e == nil || !strings.Contains(e.Error(), "listener") {
				t.Fatalf("invalid listener not rejected early: %v", e)
			}
		})
	}
	if e := apiCommand("api-serve", []string{"-state", "/unused", "-listen", "192.168.88.2:8443"}); e == nil || !strings.Contains(e.Error(), "client CIDRs") {
		t.Fatal("LAN listener accepted without explicit clients", e)
	}
	if e := apiCommand("api-serve", []string{"-state", "/unused", "unexpected"}); e == nil || !strings.Contains(e.Error(), "unexpected") {
		t.Fatal("positional arguments accepted", e)
	}
}
func apiRuntimeArgs(t *testing.T) []string {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	if e = api.InitializeAuth(dir, []byte("private-api-runtime-test-password")); e != nil {
		t.Fatal(e)
	}
	ep, e := endpoints.ParseURI("trojan://private-runtime-secret@example.org:443#fixture")
	if e != nil {
		t.Fatal(e)
	}
	m := coreconfig.Model{SchemaVersion: 2, Instance: "api-test", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{ep.ID}, Selected: ep.ID}}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.19.0.0/16", CachePath: "/data/api/cache.db"}}
	raw, _ := json.Marshal(m)
	model := filepath.Join(dir, "model.json")
	key := filepath.Join(dir, "server.key")
	if e = os.WriteFile(model, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(key, []byte("private-tls-test-fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	return []string{"-state", dir, "-config", model, "-tls-key", key, "-tls-cert", filepath.Join(dir, "not-loaded.crt")}
}
func TestAPIRuntimeProfileAndRefreshPreflightDenyUnsafeInputs(t *testing.T) {
	args := apiRuntimeArgs(t)
	for _, interval := range []string{"1s", "25h", "-1m"} {
		e := apiCommand("api-serve", append(append([]string{}, args...), "-subscription-refresh", interval))
		if e == nil || !strings.Contains(e.Error(), "refresh interval") {
			t.Fatal("unsafe periodic interval accepted", interval, e)
		}
	}
	e := apiCommand("api-serve", append(append([]string{}, args...), "-runtime-profile", privateFixture(t, `{"schema":1}`)))
	if e == nil || !strings.Contains(e.Error(), "HTTPS router") {
		t.Fatal("runtime accepted without router", e)
	}
	router := privateFixture(t, `{"base_url":"https://127.0.0.1:9/rest","username":"api-test","password":"private-runtime-secret"}`)
	malformed := privateFixture(t, `{"schema":1,"schema":2}`)
	e = apiCommand("api-serve", append(append([]string{}, args...), "-router-config", router, "-runtime-profile", malformed))
	if e == nil || !strings.Contains(e.Error(), "invalid runtime profile") || strings.Contains(e.Error(), "private-runtime-secret") {
		t.Fatal("unsafe runtime profile or error accepted", e)
	}
	for _, client := range []string{"0.0.0.0/0", "::/0", "not-a-CIDR"} {
		e = apiCommand("api-serve", append(append([]string{}, args...), "-allow-clients", client))
		if e == nil || strings.Contains(e.Error(), "private-runtime-secret") {
			t.Fatal("invalid/unbounded clients accepted", client, e)
		}
	}
}
