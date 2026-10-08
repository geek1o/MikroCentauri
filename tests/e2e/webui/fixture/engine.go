package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/enginecontrol"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// previewEngine runs a real local SOCKS engine; no TUN or RouterOS steering.
type previewEngine struct {
	mu                  sync.Mutex
	binary, dir, secret string
	port                uint16
	cmd                 *exec.Cmd
	done                chan struct{}
	client              *enginecontrol.Client
}

func (e *previewEngine) stop() {
	if e.cmd != nil {
		e.cmd.Process.Kill()
		<-e.done
		e.cmd = nil
	}
}
func (e *previewEngine) Close() { e.mu.Lock(); defer e.mu.Unlock(); e.stop() }
func freePort() uint16 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("private listener unavailable")
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func (e *previewEngine) Start(ctx context.Context, m coreconfig.Model) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		e.secret = hex.EncodeToString(b)
		e.port = freePort()
		c, err := enginecontrol.New(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(e.port))), e.secret)
		if err != nil {
			return err
		}
		e.client = c
	}
	data, err := coreconfig.GenerateWithOptions(m, coreconfig.Options{DNSPort: freePort(), MixedPort: freePort(), CachePath: filepath.Join(e.dir, "preview-engine-cache.db"), ControlPort: e.port, ControlSecret: e.secret})
	if err != nil {
		return err
	}
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return errors.New("invalid preview engine")
	}
	in := []any{}
	for _, v := range raw["inbounds"].([]any) {
		if v.(map[string]any)["type"] != "tun" {
			in = append(in, v)
		}
	}
	raw["inbounds"] = in
	data, err = json.Marshal(raw)
	if err != nil {
		return err
	}
	path := filepath.Join(e.dir, "preview-engine.json")
	if config.WriteAtomic(path, data) != nil {
		return errors.New("private preview configuration unavailable")
	}
	check := exec.CommandContext(ctx, e.binary, "check", "-c", path)
	if check.Run() != nil {
		return errors.New("preview engine validation failed")
	}
	e.stop()
	cmd := exec.Command(e.binary, "run", "-c", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		return errors.New("preview engine start failed")
	}
	e.cmd = cmd
	e.done = make(chan struct{})
	go func() { cmd.Wait(); close(e.done) }()
	for i := 0; i < 100; i++ {
		if _, err = e.client.Snapshot(ctx); err == nil {
			return nil
		}
		select {
		case <-e.done:
			return errors.New("preview engine exited")
		case <-ctx.Done():
			e.stop()
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	e.stop()
	return errors.New("preview engine readiness timed out")
}
func (e *previewEngine) EngineSnapshot(ctx context.Context) (map[string]enginecontrol.Proxy, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client.Snapshot(ctx)
}
func (e *previewEngine) EngineSelect(ctx context.Context, g, n string, revision uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client.Select(ctx, g, n)
}
func (e *previewEngine) EngineDelay(ctx context.Context, n string) (int64, error) {
	e.mu.Lock()
	client := e.client
	e.mu.Unlock()
	return client.Delay(ctx, n)
}
