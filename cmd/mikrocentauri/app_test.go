package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/api"
)

func appSettingsFixture(t *testing.T, s appSettings) string {
	t.Helper()
	data, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	return privateFixture(t, string(data))
}

func baseAppSettings() appSettings {
	return appSettings{SchemaVersion: 1, Listen: "127.0.0.1:8443", Model: "/data/bootstrap/model.json", TLSCert: "/data/bootstrap/server.crt", TLSKey: "/data/bootstrap/server.key"}
}

func TestAppSettingsPrivateStrictAndFixedArguments(t *testing.T) {
	s := baseAppSettings()
	p := appSettingsFixture(t, s)
	loaded, e := loadAppSettings(p)
	if e != nil || loaded.DataDirectory != "/data" {
		t.Fatal(loaded, e)
	}
	if e := os.Chmod(p, 0400); e != nil {
		t.Fatal(e)
	}
	if _, e := loadAppSettings(p); e != nil {
		t.Fatal("read-only secret denied", e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := loadAppSettings(p); e == nil {
		t.Fatal("public app secret accepted")
	}
	for _, data := range []string{`{"schema_version":1,"schema_version":2}`, `{"schema_version":1,"command":"sh -c secret"}`, `{} {}`, `null`} {
		if _, e := loadAppSettings(privateFixture(t, data)); e == nil {
			t.Fatal("unsafe settings accepted", data)
		}
	}
	for _, change := range []func(*appSettings){
		func(s *appSettings) { s.Listen = "0.0.0.0:8443" },
		func(s *appSettings) { s.Listen = "8.8.8.8:8443" },
		func(s *appSettings) { s.Listen = "localhost:8443" },
		func(s *appSettings) { s.Listen = "127.0.0.1:00" },
		func(s *appSettings) { s.Listen = "127.0.0.1:65536" },
		func(s *appSettings) { s.Listen = "127.0.0.1:https" },
		func(s *appSettings) { s.Listen = "192.168.88.2:8443" },
		func(s *appSettings) { s.AllowClients = []string{"0.0.0.0/0"} },
		func(s *appSettings) { s.AllowClients = []string{"192.168.88.2/24"} },
		func(s *appSettings) { s.RuntimeProfile = "/data/profile.json" },
		func(s *appSettings) { s.DataDirectory = "/data/../private" },
		func(s *appSettings) { s.PasswordFile = "relative-password" },
	} {
		candidate := s
		change(&candidate)
		if _, e := loadAppSettings(appSettingsFixture(t, candidate)); e == nil {
			t.Fatal("invalid settings accepted", candidate.Listen)
		}
	}
	s.Listen = "192.168.88.2:8443"
	s.AllowClients = []string{"192.168.88.0/24"}
	s.DataDirectory = "/data"
	s.RouterConfig = "/data/bootstrap/router.json"
	s.RuntimeProfile = "/data/bootstrap/runtime.json"
	if _, e := loadAppSettings(appSettingsFixture(t, s)); e != nil {
		t.Fatal(e)
	}
	args := appServeArgs(s)
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-sing-box /usr/bin/sing-box", "-state /data/api", "-ruleset-state /data/rulesets", "-allow-clients 192.168.88.0/24,192.168.88.2/32", "-runtime-profile /data/bootstrap/runtime.json"} {
		if !strings.Contains(joined, expected) {
			t.Fatal("missing fixed startup option", expected)
		}
	}
	if strings.Contains(joined, "-password-file") {
		t.Fatal("bootstrap password handed to long-running API")
	}
	for _, path := range []string{"/data", "/data/../escape", "/elsewhere/cache", "/data-peer/cache"} {
		if beneathAppData("/data", path) {
			t.Fatal("persistent boundary escaped", path)
		}
	}
	if !beneathAppData("/data", "/data/runtime/cache.db") {
		t.Fatal("valid persistence path rejected")
	}
	for _, action := range []string{"app-shell", "app-health"} {
		if e := appCommand(action, []string{"unexpected"}); e == nil {
			t.Fatal("unexpected action or positional accepted")
		}
	}
}

func TestAppAuthenticationBootstrapPreservesExistingState(t *testing.T) {
	state, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(state, 0700); e != nil {
		t.Fatal(e)
	}
	password := "unique-first-run-password-for-app"
	p := privateFixture(t, password+"\n")
	if e := os.Chmod(p, 0400); e != nil {
		t.Fatal(e)
	}
	if e := initializeAppAuth(state, p); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(state, "auth.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(before), password) {
		t.Fatal("password persisted as plaintext")
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e := initializeAppAuth(state, p); e != nil {
		t.Fatal("restart demanded removed bootstrap secret", e)
	}
	after, e := os.ReadFile(filepath.Join(state, "auth.json"))
	if e != nil || string(before) != string(after) {
		t.Fatal("existing credentials rewritten", e)
	}
	a, e := api.OpenAuth(state)
	if e != nil {
		t.Fatal(e)
	}
	if _, status := a.Login(password); status != 200 {
		t.Fatal("original credentials lost", status)
	}
	if e := initializeAppAuth(state, ""); e == nil {
		t.Fatal("duplicate API owner accepted")
	}
	a.Close()
	if e := os.WriteFile(filepath.Join(state, "auth.json"), []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := initializeAppAuth(state, privateFixture(t, "replacement-password-must-not-reset")); e == nil {
		t.Fatal("corrupt credentials reset")
	}
	corrupt, _ := os.ReadFile(filepath.Join(state, "auth.json"))
	if string(corrupt) != "corrupt" {
		t.Fatal("corrupt state replaced")
	}
}

func TestAppAuthenticationRejectsMissingPublicShortAndSymlinkPassword(t *testing.T) {
	public := privateFixture(t, "private-password-for-app-test")
	if e := os.Chmod(public, 0644); e != nil {
		t.Fatal(e)
	}
	link := public + "-link"
	if e := os.Symlink(public, link); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"", public, link, privateFixture(t, "short")} {
		state, e := filepath.EvalSymlinks(t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		os.Chmod(state, 0700)
		if e := initializeAppAuth(state, path); e == nil {
			t.Fatal("unsafe bootstrap accepted")
		}
		if _, e := os.Stat(filepath.Join(state, "auth.json")); !os.IsNotExist(e) {
			t.Fatal("failed bootstrap wrote auth", e)
		}
	}
}

func TestAppTLSLivenessHonestAndBounded(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		accepted   bool
	}{
		{"live", `{"live":true}`, 200, true},
		{"false", `{"live":false}`, 200, false},
		{"null", `{"live":null}`, 200, false},
		{"readiness", `{"ready":true}`, 200, false},
		{"extra", `{"live":true,"ready":true}`, 200, false},
		{"duplicate", `{"live":false,"live":true}`, 200, false},
		{"large", strings.Repeat(" ", 513) + `{"live":true}`, 200, false},
		{"unavailable", `{"live":true}`, 503, false},
		{"redirect", `{"live":true}`, 302, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/health/live" || r.Method != "GET" || r.Header.Get("Authorization") != "" {
					t.Error("health requested wrong contract")
				}
				w.Header().Set("Location", "https://127.0.0.1:1/private")
				w.WriteHeader(test.status)
				w.Write([]byte(test.body))
			}))
			srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
			srv.StartTLS()
			defer srv.Close()
			ca := filepath.Join(filepath.Dir(privateFixture(t, `{}`)), "ca.pem")
			if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0644); e != nil {
				t.Fatal(e)
			}
			s := appSettings{Listen: strings.TrimPrefix(srv.URL, "https://"), TLSCert: ca}
			e := appHealth(context.Background(), s)
			if (e == nil) != test.accepted {
				t.Fatal("incorrect liveness", e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e := appHealth(ctx, s); e == nil {
				t.Fatal("cancelled liveness accepted")
			}
			s.TLSCA = privateFixture(t, "not-a-certificate")
			if e := appHealth(context.Background(), s); e == nil {
				t.Fatal("bad trust accepted")
			}
		})
	}
	old := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"live":true}`)) }))
	old.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	old.StartTLS()
	defer old.Close()
	ca := filepath.Join(filepath.Dir(privateFixture(t, `{}`)), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Certificate().Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	if e := appHealth(context.Background(), appSettings{Listen: strings.TrimPrefix(old.URL, "https://"), TLSCert: ca}); e == nil {
		t.Fatal("TLS1.2 liveness accepted")
	}
}

// This subprocess exercises the exact serve argv used by app-run without
// requiring a host /data mount or pretending macOS supports native Linux TUN.
func TestAppAPIProcess(t *testing.T) {
	path := os.Getenv("MIKROCENTAURI_TEST_APP_SETTINGS")
	if path == "" {
		return
	}
	s, e := loadAppSettings(path)
	if e == nil {
		e = apiCommand("api-serve", appServeArgs(s))
	}
	if e != nil {
		t.Fatal(e)
	}
}

func TestAppAPILifecycleTLSLivenessAndUnreadyRuntime(t *testing.T) {
	testAppAPILifecycle(t, "")
}

func TestAppAPIMappedOriginLivenessAndAuthentication(t *testing.T) {
	testAppAPILifecycle(t, "https://127.0.0.1:18443")
}

type appOriginTransport struct {
	base   http.RoundTripper
	origin string
}

func (o appOriginTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = strings.TrimPrefix(o.origin, "https://")
	r.Header.Set("Origin", o.origin)
	return o.base.RoundTrip(r)
}

func testAppAPILifecycle(t *testing.T, publicOrigin string) {
	args := apiRuntimeArgs(t)
	directory := filepath.Dir(args[3])
	s := appSettings{SchemaVersion: 1, DataDirectory: directory, Listen: "", PublicOrigin: publicOrigin, Model: args[3], TLSCert: filepath.Join(directory, "app.crt"), TLSKey: filepath.Join(directory, "app.key")}
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.Listen = strings.TrimPrefix(certificateServer.URL, "https://")
	certificate := certificateServer.TLS.Certificates[0]
	certificateServer.Close()
	key, e := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(s.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(s.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0400); e != nil {
		t.Fatal(e)
	}
	password := "private-app-process-fixture-password"
	p := privateFixture(t, password)
	if e := initializeAppAuth(filepath.Join(directory, "api"), p); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	settingsPath := appSettingsFixture(t, s)
	before, e := os.ReadFile(filepath.Join(directory, "api", "auth.json"))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	// Password derivation under the race detector is CPU-bound on shared runners.
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	if publicOrigin != "" {
		client.Transport = appOriginTransport{base: transport, origin: publicOrigin}
	}
	for restart := 0; restart < 2; restart++ {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestAppAPIProcess$")
		cmd.Env = append(os.Environ(), "MIKROCENTAURI_TEST_APP_SETTINGS="+settingsPath)
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
		}
		finished := make(chan error, 1)
		go func() { finished <- cmd.Wait() }()
		deadline := time.Now().Add(5 * time.Second)
		for appHealth(context.Background(), s) != nil {
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				<-finished
				t.Fatal("API did not become live", output.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		login, _ := json.Marshal(map[string]string{"password": password})
		resp, e := client.Post("https://"+s.Listen+"/api/v1/auth/login", "application/json", bytes.NewReader(login))
		if e != nil {
			cmd.Process.Kill()
			<-finished
			t.Fatal(e)
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		e = json.NewDecoder(resp.Body).Decode(&token)
		resp.Body.Close()
		if e != nil || resp.StatusCode != 200 || len(token.AccessToken) != 64 {
			cmd.Process.Kill()
			<-finished
			t.Fatal("persistent login failed", resp.StatusCode, e)
		}
		request, _ := http.NewRequest("GET", "https://"+s.Listen+"/api/v1/health/ready", nil)
		request.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, e = client.Do(request)
		if e != nil {
			cmd.Process.Kill()
			<-finished
			t.Fatal(e)
		}
		var readiness struct {
			Ready bool `json:"ready"`
		}
		e = json.NewDecoder(resp.Body).Decode(&readiness)
		resp.Body.Close()
		if e != nil || resp.StatusCode != 503 || readiness.Ready {
			cmd.Process.Kill()
			<-finished
			t.Fatal("API-only startup fabricated dataplane readiness")
		}
		if e := cmd.Process.Signal(syscall.SIGTERM); e != nil {
			cmd.Process.Kill()
			<-finished
			t.Fatal(e)
		}
		select {
		case e := <-finished:
			if e != nil {
				t.Fatal("SIGTERM shutdown failed", e, output.String())
			}
		case <-time.After(8 * time.Second):
			cmd.Process.Kill()
			<-finished
			t.Fatal("SIGTERM shutdown exceeded bound")
		}
		if appHealth(context.Background(), s) == nil {
			t.Fatal("stopped API still live")
		}
		after, e := os.ReadFile(filepath.Join(directory, "api", "auth.json"))
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("restart changed persisted credentials", e)
		}
	}
}
