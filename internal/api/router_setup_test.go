package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/platform/routeros"
)

type setupRouterFixture struct{ failure error }

func (f *setupRouterFixture) Capabilities(context.Context) (routeros.Capabilities, error) {
	return routeros.Capabilities{Version: "7.23.8 (long-term)", Architecture: "arm64", Board: "fixture", VersionSupported: false, Resources: map[string]bool{}, Packages: []routeros.Package{}, Interfaces: []routeros.Interface{}}, f.failure
}
func (f *setupRouterFixture) Discover(context.Context) ([]routeros.Object, error) {
	return []routeros.Object{}, f.failure
}
func (f *setupRouterFixture) Network(context.Context) (routeros.Network, error) {
	return routeros.Network{Available: map[string]bool{}, DefaultRoutes: []routeros.NetworkRoute{}, Devices: []routeros.NetworkDevice{}, DNSServers: []string{}, IPv6: routeros.IPv6Observation{State: "unknown"}, Addresses: []routeros.NetworkAddress{{Address: "192.168.88.1/24", Interface: "bridge"}}}, f.failure
}
func TestRouterSetupVerifiedPersistenceRedactionAndReopen(t *testing.T) {
	s, a, token := setup(t, nil)
	input := RouterSetupInput{BaseURL: "https://192.168.88.1/rest", Username: "mc-reader", Password: "private-setup-password-canary"}
	probes := 0
	s.opts.SetupProbe = func(_ context.Context, got RouterSetupInput) (RouterClient, error) {
		probes++
		if got != input {
			t.Fatal("credentials changed")
		}
		return &setupRouterFixture{}, nil
	}
	for _, path := range []string{"/api/v1/setup/router/test", "/api/v1/setup/router/save"} {
		w := call(s, "POST", path, token, input)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), input.Password) {
			t.Fatal("password exposed")
		}
		contractResponse(t, OpenAPI(), "POST", path, w)
		if strings.HasSuffix(path, "test") {
			if _, e := os.Stat(filepath.Join(s.dir, "router-connection.json")); !os.IsNotExist(e) {
				t.Fatal("test persisted credentials")
			}
		}
	}
	file := filepath.Join(s.dir, "router-connection.json")
	info, e := os.Stat(file)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unprotected credentials", e)
	}
	for _, path := range []string{"/api/v1/setup/router", "/api/v1/setup/preflight", "/api/v1/logs", "/api/v1/backup"} {
		w := call(s, "GET", path, token, nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), input.Password) {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if strings.HasPrefix(path, "/api/v1/setup/") {
			contractResponse(t, OpenAPI(), "GET", path, w)
		}
	}
	w := call(s, "GET", "/api/v1/setup/preflight", token, nil)
	var pre SetupPreflight
	json.Unmarshal(w.Body.Bytes(), &pre)
	if pre.AutomaticInstallAvailable || pre.RoutingReady || pre.RuntimeConnected {
		t.Fatal("read-only connection claims routing")
	}
	// Empty fields reuse credentials only for the same endpoint/account.
	reused := input
	reused.Password = ""
	if w := call(s, "POST", "/api/v1/setup/router/test", token, reused); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	before := probes
	reused.BaseURL = "https://192.168.88.2/rest"
	if w := call(s, "POST", "/api/v1/setup/router/test", token, reused); w.Code != 400 || probes != before {
		t.Fatal("credentials forwarded to new destination")
	}
	reopened, e := New(Options{Directory: s.dir, Auth: a, Model: fixture(t), Origin: s.opts.Origin})
	if e != nil {
		t.Fatal(e)
	}
	status := reopened.setupStatus()
	if !status.Configured || !status.HasPassword || status.BaseURL != input.BaseURL {
		t.Fatal("saved connection not restored")
	}
	if reopened.opts.Router == nil {
		t.Fatal("read-only resources unavailable after restart")
	}
	s.opts.SetupProbe = func(context.Context, RouterSetupInput) (RouterClient, error) {
		return &setupRouterFixture{failure: errors.New("HTTP 403 private-setup-password-canary")}, nil
	}
	changed := input
	changed.Password = "new-private-credential"
	w = call(s, "POST", "/api/v1/setup/router/save", token, changed)
	if w.Code != 422 || strings.Contains(w.Body.String(), "canary") {
		t.Fatal("failed probe leaked credentials or saved", w.Code)
	}
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), changed.Password) {
		t.Fatal("failed probe changed persistent connection")
	}
}
func TestRouterSetupRejectsUnsafeTargetsAndNativeOwnerChanges(t *testing.T) {
	s, _, token := setup(t, nil)
	input := RouterSetupInput{BaseURL: "https://192.168.88.1/rest", Username: "mc", Password: "private"}
	for _, base := range []string{"http://192.168.88.1/rest", "https://8.8.8.8/rest", "https://localhost/rest", "https://127.0.0.1/rest", "https://192.168.88.1/rest?password=canary", "https://mc:secret@192.168.88.1/rest", "https://192.168.88.1/other"} {
		in := input
		in.BaseURL = base
		if w := call(s, "POST", "/api/v1/setup/router/save", token, in); w.Code != 400 {
			t.Fatal(base, w.Code)
		}
	}
	if w := call(s, "POST", "/api/v1/setup/router/save", "", input); w.Code != 401 {
		t.Fatal("unauthenticated setup")
	}
	input.CertificatePEM = "private-not-a-certificate"
	if w := call(s, "POST", "/api/v1/setup/router/save", token, input); w.Code != 400 || strings.Contains(w.Body.String(), input.CertificatePEM) {
		t.Fatal("invalid certificate accepted or echoed")
	}
	s.opts.Runtime = &fakeRuntime{m: fixture(t)}
	if w := call(s, "POST", "/api/v1/setup/router/save", token, input); w.Code != 409 {
		t.Fatal("native connection mutated")
	}
}
