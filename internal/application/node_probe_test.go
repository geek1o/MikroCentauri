package application

import (
	"context"
	"encoding/json"
	"io"
	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type nodeOwner struct {
	observerOwner
	model coreconfig.Model
}

func (o *nodeOwner) CurrentModel() (coreconfig.Model, error) { return o.model.Clone() }
func TestPinnedNodeProbeIsolatesEndpointAndFailsWithoutDirectFallback(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for actual isolated child proof")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "live-engine-cache-sentinel")
	os.WriteFile(sentinel, []byte("unchanged engine cache"), 0600)
	var observed atomic.Int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		entries, e := filepath.Glob(filepath.Join(dir, ".node-probe-*", "candidate.json"))
		if e != nil || len(entries) != 1 {
			t.Error("private probe candidate absent")
			w.WriteHeader(500)
			return
		}
		candidate, _ := os.ReadFile(entries[0])
		var cfg map[string]any
		if json.Unmarshal(candidate, &cfg) != nil {
			t.Error("invalid probe candidate")
			w.WriteHeader(500)
			return
		}
		for _, in := range cfg["inbounds"].([]any) {
			entry := in.(map[string]any)
			if entry["type"] == "tun" || entry["listen"] != "127.0.0.1" {
				t.Error("probe opened TUN/nonlocal ingress")
			}
		}
		cache := cfg["experimental"].(map[string]any)["cache_file"].(map[string]any)
		if cache["store_fakeip"] != false || !strings.HasPrefix(cache["path"].(string), filepath.Dir(entries[0])+string(os.PathSeparator)) {
			t.Error("probe used live FakeIP cache")
		}
		file, _ := os.Stat(entries[0])
		parent, _ := os.Stat(filepath.Dir(entries[0]))
		if file.Mode().Perm() != 0600 || parent.Mode().Perm() != 0700 {
			t.Error("credential permissions")
		}
		observed.Add(1)
		io.WriteString(w, `{"remote_ip":"127.0.0.1"}`)
	}))
	defer canary.Close()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port, "method": "aes-256-gcm", "password": "DisposableNodeProbeOnly"}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}}
	raw, _ := json.Marshal(cfg)
	serverPath := filepath.Join(t.TempDir(), "ss-server.json")
	os.WriteFile(serverPath, raw, 0600)
	if e = singbox.Check(context.Background(), binary, serverPath); e != nil {
		t.Fatal(e)
	}
	server := exec.Command(binary, "run", "-c", serverPath)
	server.Stdout = io.Discard
	server.Stderr = io.Discard
	if server.Start() != nil {
		t.Fatal("server start")
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			server.Process.Kill()
			server.Wait()
		}
	}
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server readiness")
		}
		time.Sleep(20 * time.Millisecond)
	}
	endpoint, e := endpoints.ParseURI("ss://aes-256-gcm:DisposableNodeProbeOnly@" + address + "#probe")
	if e != nil {
		t.Fatal(e)
	}
	m := testModel(t)
	m.Endpoints = []endpoints.Endpoint{endpoint}
	m.Groups = nil
	m.DefaultOutbound = "direct"
	m.Rules = []coreconfig.Rule{{ID: "global-direct", Domains: []string{"example.org"}, Outbound: "direct"}}
	host, e := api.NewHost(api.HostOptions{Core: &nodeOwner{model: m}, Reconcile: func(context.Context) error { return nil }, Probe: func(context.Context) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	runtime := &Runtime{Host: host, binary: binary, Profile: Profile{Directory: dir, CanaryURL: canary.URL}}
	latency, e := runtime.ProbeNode(context.Background(), endpoint.ID)
	if e != nil || latency <= 0 || observed.Load() != 1 {
		t.Fatal("actual node probe", latency, e, observed.Load())
	}
	checkClean := func() {
		t.Helper()
		left, _ := filepath.Glob(filepath.Join(dir, ".node-probe-*"))
		original, _ := os.ReadFile(sentinel)
		if len(left) != 0 || string(original) != "unchanged engine cache" {
			t.Fatal("probe left private children/cache or touched unrelated file")
		}
	}
	checkClean()
	stop()
	if _, e = runtime.ProbeNode(context.Background(), endpoint.ID); e == nil || observed.Load() != 1 {
		t.Fatal("unavailable node fell back DIRECT", e, observed.Load())
	}
	checkClean()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = runtime.ProbeNode(canceled, endpoint.ID); e == nil {
		t.Fatal("canceled probe continued")
	}
	checkClean()
	if _, e = runtime.ProbeNode(context.Background(), strings.Repeat("f", 64)); e == nil {
		t.Fatal("unknown endpoint accepted")
	}
	checkClean()
}
