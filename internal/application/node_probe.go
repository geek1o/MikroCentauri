package application

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProbeNode isolates a single active endpoint in a short-lived socksify child.
// It has no TUN, RouterOS adapter, fallback group, FakeIP publication or reference
// to the live engine cache. Targets and binary are private operator composition.
func (r *Runtime) ProbeNode(ctx context.Context, id string) (latency time.Duration, err error) {
	err = r.Host.Inspect(ctx, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		m, e := r.Model()
		if e != nil {
			return e
		}
		isolated := coreconfig.Model{SchemaVersion: 2, Instance: m.Instance, Mode: "socksify", DefaultOutbound: id, DNS: m.DNS}
		isolated.DNS.SelectedDomains = nil
		isolated.DNS.SelectedSuffixes = nil
		for _, node := range m.Endpoints {
			if node.ID == id && node.Enabled {
				isolated.Endpoints = append(isolated.Endpoints, node)
			}
		}
		for _, node := range m.WireGuard {
			if node.ID == id && node.Enabled {
				isolated.WireGuard = append(isolated.WireGuard, node)
			}
		}
		if len(isolated.Endpoints)+len(isolated.WireGuard) != 1 {
			return errors.New("active node absent")
		}
		dir, e := os.MkdirTemp(r.Profile.Directory, ".node-probe-")
		if e != nil {
			return errors.New("probe directory unavailable")
		}
		defer os.RemoveAll(dir)
		// MkdirTemp uses 0700. Configuration and the independent cache remain inside
		// this directory and are removed only after the child has been reaped.
		dns, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return e
		}
		defer dns.Close()
		mixed, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return e
		}
		defer mixed.Close()
		dnsPort := uint16(dns.Addr().(*net.TCPAddr).Port)
		mixedPort := uint16(mixed.Addr().(*net.TCPAddr).Port)
		candidate, e := coreconfig.GenerateWithOptions(isolated, coreconfig.Options{DNSPort: dnsPort, MixedPort: mixedPort, CachePath: filepath.Join(dir, "independent-cache.db")})
		if e != nil {
			return e
		}
		var generated map[string]any
		if json.Unmarshal(candidate, &generated) != nil {
			return errors.New("invalid isolated candidate")
		}
		generated["log"] = map[string]any{"level": "info", "timestamp": false}
		candidate, e = json.Marshal(generated)
		if e != nil {
			return e
		}
		path := filepath.Join(dir, "candidate.json")
		if os.WriteFile(path, candidate, 0600) != nil {
			return errors.New("probe candidate unavailable")
		}
		if e = singbox.Check(ctx, r.binary, path); e != nil {
			return e
		}
		dns.Close()
		mixed.Close()
		command := exec.CommandContext(ctx, r.binary, "run", "-c", path)
		command.Stdout = io.Discard
		stderr, e := command.StderrPipe()
		if e != nil {
			return errors.New("probe readiness unavailable")
		}
		command.WaitDelay = time.Second
		if command.Start() != nil {
			return errors.New("probe child unavailable")
		}
		ready := make(chan struct{})
		logDone := make(chan struct{})
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(mixedPort)))
		go func() {
			defer close(logDone)
			scanner := bufio.NewScanner(stderr)
			scanner.Buffer(make([]byte, 4096), 64<<10)
			listening, started := false, false
			published := false
			for scanner.Scan() {
				line := scanner.Text()
				listening = listening || strings.Contains(line, "inbound/mixed[explicit-in]: tcp server started at "+address)
				started = started || strings.Contains(line, "sing-box started (")
				if listening && started && !published {
					published = true
					close(ready)
				}
			}
		}()
		done := make(chan struct{})
		go func() { command.Wait(); close(done) }()
		defer func() { cancel(); <-done; <-logDone }()
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return errors.New("probe child exited")
		case <-logDone:
			return errors.New("probe startup not observed")
		}
		select {
		case <-done:
			return errors.New("probe child exited")
		default:
		}
		for {
			connection, e := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if e == nil {
				connection.Close()
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-done:
				return errors.New("probe child exited")
			case <-time.After(20 * time.Millisecond):
			}
		}
		// A fresh local SOCKS5 connection reaches the fixed literal canary. The child
		// final route is this node, so no global selector or DIRECT fallback is used.
		proxyURL, _ := url.Parse("socks5://" + address)
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		started := time.Now()
		e = canaryRequest(ctx, client, r.Profile.CanaryURL)
		latency = time.Since(started)
		if e == nil {
			select {
			case <-done:
				return errors.New("probe child exited")
			default:
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		return e
	})
	return latency, err
}
