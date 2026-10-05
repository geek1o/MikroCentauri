package coreconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is a process/socket integration proof of the generated SOCKS/HTTP engine,
// not a native RouterOS transparent TUN or external FakeIP admission proof.
func TestPinnedMixedRuntimeRoutes(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for real process integration")
	}
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct-target") }))
	defer direct.Close()
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "proxy-target") }))
	defer proxied.Close()
	serverPort := freePort(t)
	dnsPort := freePort(t)
	mixedPort := freePort(t)
	forward, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var connections atomic.Int64
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			c, e := forward.Accept()
			if e != nil {
				return
			}
			connections.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				up, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), time.Second)
				if e != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(up, c)
					if tcp, ok := up.(*net.TCPConn); ok {
						tcp.CloseWrite()
					}
					close(done)
				}()
				io.Copy(c, up)
				c.Close()
				<-done
			}()
		}
	}()
	defer func() { forward.Close(); <-stopped; workers.Wait() }()
	dir := t.TempDir()
	serverConfig := object{"log": object{"level": "warn"}, "inbounds": []object{{"type": "shadowsocks", "tag": "ss-in", "listen": "127.0.0.1", "listen_port": serverPort, "method": "aes-256-gcm", "password": "public-test-secret"}}, "outbounds": []object{{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct"}}
	serverPath := filepath.Join(dir, "server.json")
	writeJSON(t, serverPath, serverConfig)
	if e = singbox.Check(context.Background(), binary, serverPath); e != nil {
		t.Fatal(e)
	}
	stopServer := runPinned(t, binary, serverPath, serverPort)
	defer stopServer()
	ep, e := endpoints.ParseURI("ss://aes-256-gcm:public-test-secret@" + forward.Addr().String() + "#runtime-fixture")
	if e != nil {
		t.Fatal(e)
	}
	directURL, _ := url.Parse(direct.URL)
	port64, _ := strconv.ParseUint(directURL.Port(), 10, 16)
	m := Model{SchemaVersion: 2, Instance: "runtime", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, Groups: []Group{{ID: "manual", Type: "selector", Members: []string{ep.ID}}}, Rules: []Rule{{ID: "direct-service", Ports: []uint16{uint16(port64)}, Outbound: "direct"}}, DefaultOutbound: "manual", DNS: DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/runtime/cache.db"}}
	b, e := GenerateWithOptions(m, Options{DNSPort: dnsPort, MixedPort: mixedPort})
	if e != nil {
		t.Fatal(e)
	}
	var cfg object
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	// Trusted host test adaptation replaces only the persistent cache location.
	cfg["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"] = filepath.Join(dir, "private-cache.db")
	clientPath := filepath.Join(dir, "client.json")
	writeJSON(t, clientPath, cfg)
	if e = singbox.Check(context.Background(), binary, clientPath); e != nil {
		t.Fatal(e)
	}
	stopClient := runPinned(t, binary, clientPath, mixedPort)
	defer stopClient()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := func(target, want string) {
		t.Helper()
		r, e := client.Get(target)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		body, e := io.ReadAll(io.LimitReader(r.Body, 1024))
		if e != nil || r.StatusCode != 200 || string(body) != want {
			t.Fatalf("unexpected target response status=%d body=%q error=%v", r.StatusCode, body, e)
		}
	}
	request(direct.URL, "direct-target")
	if connections.Load() != 0 {
		t.Fatal("DIRECT rule touched the proxy endpoint")
	}
	request(proxied.URL, "proxy-target")
	if connections.Load() != 1 {
		t.Fatalf("selected proxy endpoint connections=%d want 1", connections.Load())
	}
}
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.Marshal(v)
	if e == nil {
		e = os.WriteFile(path, b, 0600)
	}
	if e != nil {
		t.Fatal(e)
	}
}
func runPinned(t *testing.T, binary, path string, port uint16) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	// Output can contain credentials: keep it out of test diagnostics.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Start(); e != nil {
		cancel()
		t.Fatal("could not start pinned process")
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); <-exited }) }
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if e == nil {
			c.Close()
			return stop
		}
		select {
		case <-exited:
			cancel()
			t.Fatal("pinned process exited before readiness")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop()
	t.Fatal("pinned process listener did not become ready")
	return stop
}
