package coreconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/enginecontrol"
)

// Exercise generated URLTest policy with two controlled CONNECT transports.
// This proves engine selection/failure recovery, not native RouterOS steering.
func TestPinnedAutomaticLatencyAndFailureRecovery(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for automatic engine proof")
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	var failed atomic.Bool
	proxy := func(delay time.Duration, reject *atomic.Bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" || (reject != nil && reject.Load()) {
				http.Error(w, "unavailable", 503)
				return
			}
			time.Sleep(delay)
			upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				http.Error(w, "unavailable", 503)
				return
			}
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			defer conn.Close()
			defer upstream.Close()
			buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			buf.Flush()
			done := make(chan struct{})
			go func() { io.Copy(upstream, buf); upstream.Close(); close(done) }()
			io.Copy(conn, upstream)
			conn.Close()
			<-done
		}))
	}
	fast, slow := proxy(5*time.Millisecond, &failed), proxy(180*time.Millisecond, nil)
	defer fast.Close()
	defer slow.Close()
	m := fixture(t)
	m.Mode = "socksify"
	m.DNS.SelectedDomains = nil
	m.Endpoints = m.Endpoints[:2]
	ids := []string{m.Endpoints[0].ID, m.Endpoints[1].ID}
	m.Groups = []Group{{ID: "auto", Type: "urltest", Members: ids, URL: target.URL, Interval: "1s", Tolerance: 50}}
	m.DefaultOutbound = "auto"
	m.Rules = nil
	m.SourceProxy = nil
	m.SourceDirect = nil
	dir := t.TempDir()
	port := freePort(t)
	mixedPort := freePort(t)
	secret := "public-automatic-test-secret-32-characters"
	data, err := GenerateWithOptions(m, Options{DNSPort: freePort(t), MixedPort: mixedPort, CachePath: filepath.Join(dir, "cache.db"), ControlPort: port, ControlSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		t.Fatal("invalid generated engine")
	}
	// Only the test transports and trust root are replaced; generated URLTest stays intact.
	cert := filepath.Join(dir, "root.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600)
	raw["certificate"] = map[string]any{"store": "none", "certificate_path": []string{cert}}
	out := raw["outbounds"].([]any)
	for i, server := range []*httptest.Server{fast, slow} {
		host, p, _ := net.SplitHostPort(server.Listener.Addr().String())
		n, _ := strconv.Atoi(p)
		out[i+1] = map[string]any{"type": "http", "tag": ids[i], "server": host, "server_port": n}
	}
	// SOCKS/HTTP input only; socksify creates no host TUN or routing changes.
	path := filepath.Join(dir, "engine.json")
	writeJSON(t, path, raw)
	stop := runPinned(t, binary, path, port)
	defer stop()
	client, err := enginecontrol.New(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), secret)
	if err != nil {
		t.Fatal(err)
	}
	wait := func(want string) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			state, e := client.Snapshot(context.Background())
			if e == nil && state["auto"].Now == want && len(state[want].History) > 0 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("automatic engine failed to select expected healthy member")
	}
	// URLTest starts its periodic ticker on first use, not merely on API polling.
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(int(mixedPort)))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Head(target.URL)
	if err != nil {
		t.Fatal("automatic group did not carry the initial request", err)
	}
	response.Body.Close()
	wait(ids[0])
	failed.Store(true)
	wait(ids[1])
	failed.Store(false)
	wait(ids[0])
}
