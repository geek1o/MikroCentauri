package grouphealth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func privateDir(t *testing.T) string {
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0700)
	return p
}
func availablePort(t *testing.T) uint16 {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func ssServer(t *testing.T, binary string, port uint16, password string) func() {
	t.Helper()
	cfg := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "aes-256-gcm", "password": password}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(privateDir(t), "server.json")
	os.WriteFile(path, b, 0600)
	if e := singbox.Check(context.Background(), binary, path); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	processAttributes(cmd)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() { once.Do(func() { stopProcess(cmd, done, time.Second) }) }
	t.Cleanup(stop)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 10*time.Millisecond)
		if e == nil {
			c.Close()
			return stop
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	t.Fatal("SS server not listening")
	return stop
}
func TestPinnedEndpointHealthAndFallback(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for native proxy probes")
	}
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9")) }))
	defer canary.Close()
	primary, secondary := availablePort(t), availablePort(t)
	stopPrimary := ssServer(t, binary, primary, "first-secret")
	stopSecondary := ssServer(t, binary, secondary, "second-secret")
	a, _ := endpoints.ParseURI("ss://aes-256-gcm:first-secret@127.0.0.1:" + strconv.Itoa(int(primary)) + "#first")
	b, _ := endpoints.ParseURI("ss://aes-256-gcm:second-secret@127.0.0.1:" + strconv.Itoa(int(secondary)) + "#second")
	p, e := NewProber(ProbeOptions{Binary: binary, Directory: privateDir(t), Timeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	cny := Canary{URL: canary.URL, ExpectedStatus: 200, ExpectedEgressIP: netip.MustParseAddr("203.0.113.9")}
	o, e := p.Probe(context.Background(), a, cny)
	if e != nil || !o.Available || o.Latency <= 0 {
		t.Fatal("genuine endpoint health", e)
	}
	wrong, _ := endpoints.ParseURI("ss://aes-256-gcm:wrong-secret@127.0.0.1:" + strconv.Itoa(int(primary)))
	if o, e = p.Probe(context.Background(), wrong, cny); e == nil || o.Available {
		t.Fatal("PID-only health or direct bypass")
	}
	m := fixture(t)
	m.Endpoints = []endpoints.Endpoint{a, b}
	m.Groups[0].Members = []string{a.ID, b.ID}
	m.Groups[0].Selected = a.ID
	applied := ""
	quarantined := false
	controller, e := New(Options{Model: m, GroupID: "fallback", TickTimeout: 10 * time.Second, Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) { return p.Probe(ctx, ep, cny) }, ApplyModel: func(ctx context.Context, next coreconfig.Model) error { applied = next.Groups[0].Selected; return nil }, Quarantine: func(context.Context) error { quarantined = true; return nil }})
	if e != nil {
		t.Fatal(e)
	}
	if e = controller.Tick(context.Background()); e != nil || applied != a.ID {
		t.Fatal("initial first selection", e)
	}
	stopPrimary()
	if e = controller.Tick(context.Background()); e != nil || applied != b.ID || controller.Status().Selected != b.ID {
		t.Fatal("failure switching", e)
	}
	stopRecovered := ssServer(t, binary, primary, "first-secret")
	if e = controller.Tick(context.Background()); e != nil || applied != a.ID {
		t.Fatal("first member recovery", e)
	}
	if quarantined {
		t.Fatal("healthy fallback was quarantined")
	}
	stopSecondary()
	stopRecovered()
	if e = controller.Tick(context.Background()); e == nil || !quarantined || controller.Status().Selected != a.ID {
		t.Fatal("all endpoints down did not quarantine")
	}

	files, _ := os.ReadDir(p.opts.Directory)
	if len(files) != 0 {
		t.Fatal("probe processes/configs not cleaned")
	}
}
func TestPinnedHTTPSStatusRedirectAndBody(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY")
	}
	port := availablePort(t)
	ssServer(t, binary, port, "test-secret")
	ep, _ := endpoints.ParseURI("ss://aes-256-gcm:test-secret@127.0.0.1:" + strconv.Itoa(int(port)))
	p, _ := NewProber(ProbeOptions{Binary: binary, Directory: privateDir(t), Timeout: 2 * time.Second})
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer tlsServer.Close()
	if o, e := p.Probe(context.Background(), ep, Canary{URL: tlsServer.URL}); e == nil || o.Available {
		t.Fatal("untrusted TLS accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	trusted, _ := NewProber(ProbeOptions{Binary: binary, Directory: privateDir(t), Timeout: 2 * time.Second, TLSRoots: roots})
	if o, e := trusted.Probe(context.Background(), ep, Canary{URL: tlsServer.URL}); e != nil || !o.Available {
		t.Fatal("trusted HTTPS canary", e)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/okay", 302)
		case "/large":
			w.Write([]byte("too-large"))
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	for _, c := range []Canary{{URL: srv.URL}, {URL: srv.URL + "/redirect"}, {URL: srv.URL + "/large", ExpectedStatus: 200, MaxBytes: 2}} {
		if o, e := p.Probe(context.Background(), ep, c); e == nil || o.Available {
			t.Fatal("invalid canary success")
		}
	}
	ep.Enabled = false
	if o, e := p.Probe(context.Background(), ep, Canary{URL: srv.URL}); e == nil || o.Available {
		t.Fatal("disabled endpoint probed")
	}
}
