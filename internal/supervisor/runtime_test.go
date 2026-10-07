package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinnedSupervisorLifecycle(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for real supervisor integration")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ready-fixture") }))
	defer target.Close()
	var released atomic.Bool
	options := Options{
		Binary: binary, Directory: dir, ReadyTimeout: 600 * time.Millisecond, StopTimeout: time.Second,
		Semantic: func(b []byte) error {
			var cfg map[string]any
			if json.Unmarshal(b, &cfg) != nil {
				return errors.New("invalid fixture model")
			}
			return nil
		},
		Hooks: Hooks{
			Quarantine: func(context.Context) error { released.Store(false); return nil },
			Prepare:    func(context.Context, string) error { return nil },
			Probe: func(ctx context.Context, path string) error {
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				var cfg struct {
					Inbounds []struct {
						Listen string `json:"listen"`
						Port   int    `json:"listen_port"`
					} `json:"inbounds"`
				}
				if json.Unmarshal(b, &cfg) != nil || len(cfg.Inbounds) != 1 {
					return errors.New("invalid fixture listener")
				}
				proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", cfg.Inbounds[0].Listen, cfg.Inbounds[0].Port))
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 100 * time.Millisecond}
				for ctx.Err() == nil {
					req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
					response, e := client.Do(req)
					if e == nil {
						body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
						response.Body.Close()
						if readErr == nil && response.StatusCode == 200 && string(body) == "ready-fixture" {
							return nil
						}
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(20 * time.Millisecond):
					}
				}
				return ctx.Err()
			},
			Release: func(context.Context) error {
				b, err := os.ReadFile(filepath.Join(dir, "journal.json"))
				var j journal
				if err != nil || json.Unmarshal(b, &j) != nil || j.Active == "" || j.Pending != "" {
					return errors.New("release preceded durable commit")
				}
				released.Store(true)
				return nil
			},
		},
	}
	s, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close(context.Background()) }()
	port := runtimePort(t)
	first := runtimeConfig(port, "mixed")
	if err = s.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	initial := s.Status()
	if !initial.Ready || !initial.Live || initial.PID == 0 || !released.Load() {
		t.Fatal("real child not ready")
	}
	if err = s.Apply(context.Background(), runtimeConfig(port, "invalid-inbound")); err == nil {
		t.Fatal("bad native schema accepted")
	}
	if after := s.Status(); after.PID != initial.PID || after.Revision != initial.Revision || !after.Ready || !released.Load() {
		t.Fatal("invalid candidate disturbed active child")
	}
	// A configuration can pass sing-box check but fail to start on an occupied socket.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Apply(context.Background(), runtimeConfig(uint16(busy.Addr().(*net.TCPAddr).Port), "mixed")); err == nil {
		busy.Close()
		t.Fatal("occupied listener unexpectedly activated")
	}
	busy.Close()
	if after := s.Status(); !after.Ready || after.Revision != initial.Revision || !released.Load() {
		t.Fatal("runtime failure did not restore LKG")
	}
	if err = s.Apply(context.Background(), runtimeConfig(runtimePort(t), "mixed")); err != nil {
		t.Fatal(err)
	}
	current := s.Status()
	if current.Revision == initial.Revision || !current.Ready {
		t.Fatal("new revision not activated")
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if released.Load() {
		t.Fatal("stop left gate released")
	}
	s, err = New(options)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reopened := s.Status(); reopened.Revision != current.Revision || !reopened.Ready {
		t.Fatal("reopened supervisor lost LKG")
	}
}

func runtimePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func runtimeConfig(port uint16, kind string) []byte {
	b, _ := json.Marshal(map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []map[string]any{{"type": kind, "listen": "127.0.0.1", "listen_port": port, "tag": "fixture"}},
		"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
	return b
}
