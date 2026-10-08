package enginecontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPrivateBridgeBoundsAndFixedLatencyTarget(t *testing.T) {
	secret := strings.Repeat("a", 32)
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("missing controller authentication")
		}
		switch {
		case r.Method == "PUT":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["name"] != "node" {
				t.Error("wrong selection")
			}
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/delay"):
			if r.URL.Query().Get("url") != "https://www.gstatic.com/generate_204" || r.URL.Query().Get("timeout") != "5000" {
				t.Error("unbounded or arbitrary latency target")
			}
			fmt.Fprint(w, `{"delay":42}`)
		default:
			fmt.Fprint(w, `{"proxies":{"group":{"type":"Selector","now":"node","all":["node"]}}}`)
		}
	}))
	defer s.Close()
	c, e := New(strings.TrimPrefix(s.URL, "http://"), secret)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	p, e := c.Snapshot(ctx)
	if e != nil || p["group"].Now != "node" {
		t.Fatal(p, e)
	}
	if c.Select(ctx, "group", "node") != nil {
		t.Fatal("selection failed")
	}
	d, e := c.Delay(ctx, "node")
	if e != nil || d != 42 || calls != 3 {
		t.Fatal(d, e, calls)
	}
	for _, address := range []string{"example.org:9090", "192.168.1.1:9090", "127.0.0.1:0"} {
		if _, e := New(address, secret); e == nil {
			t.Fatal("unsafe address accepted")
		}
	}
	if _, e := New("127.0.0.1:9090", "short"); e == nil {
		t.Fatal("weak secret accepted")
	}
}
func TestSelectionAgainstRealPinnedSingBox(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("pinned engine not supplied")
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := l.Addr().String()
	l.Close()
	secret := strings.Repeat("c", 64)
	dir := t.TempDir()
	config := map[string]any{"outbounds": []any{map[string]any{"type": "direct", "tag": "a"}, map[string]any{"type": "direct", "tag": "b"}, map[string]any{"type": "selector", "tag": "choice", "outbounds": []string{"a", "b"}, "default": "a"}}, "experimental": map[string]any{"clash_api": map[string]any{"external_controller": address, "secret": secret}}}
	raw, _ := json.Marshal(config)
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, raw, 0600)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cancel(); cmd.Wait() }()
	pid := cmd.Process.Pid
	c, _ := New(address, secret)
	ready := false
	for i := 0; i < 100; i++ {
		p, e := c.Snapshot(ctx)
		if e == nil && p["choice"].Now == "a" {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real engine never became ready")
	}
	if e = c.Select(ctx, "choice", "b"); e != nil {
		t.Fatal(e)
	}
	p, e := c.Snapshot(ctx)
	if e != nil || p["choice"].Now != "b" || cmd.Process.Pid != pid {
		t.Fatal("live selection not confirmed", p, e)
	}
	port, _ := strconv.Atoi(strings.Split(address, ":")[1])
	if port == 0 {
		t.Fatal("invalid listener")
	}
}
