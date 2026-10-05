// Package grouphealth observes each endpoint through an isolated, checked proxy
// process. It never probes by modifying the selection of the active dataplane.
package grouphealth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Canary struct {
	URL              string
	ExpectedStatus   int
	ExpectedEgressIP netip.Addr
	MaxBytes         int64
}
type Observation struct {
	coreconfig.Health
	EndpointID string    `json:"endpoint_id"`
	CheckedAt  time.Time `json:"checked_at"`
	Failure    string    `json:"failure,omitempty"`
}
type ProbeOptions struct {
	Binary, Directory, Bootstrap string
	Timeout, StopTimeout         time.Duration
	TLSRoots                     *x509.CertPool
	Concurrency                  int
}
type Prober struct {
	opts         ProbeOptions
	sem          chan struct{}
	mu           sync.Mutex
	observations map[string]Observation
}

func NewProber(o ProbeOptions) (*Prober, error) {
	if o.Directory == "" || o.Binary == "" {
		return nil, errors.New("probe executable and directory required")
	}
	binary, e := filepath.Abs(o.Binary)
	if e != nil {
		return nil, errors.New("invalid probe executable")
	}
	st, e := os.Stat(binary)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("probe executable unavailable")
	}
	o.Binary = binary
	dir, e := filepath.Abs(o.Directory)
	if e != nil || privateParents(dir) != nil {
		return nil, errors.New("unsafe probe directory")
	}
	if os.MkdirAll(dir, 0700) != nil {
		return nil, errors.New("probe directory unavailable")
	}
	st, e = os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("probe directory must be private")
	}
	o.Directory = dir
	if o.Bootstrap == "" {
		o.Bootstrap = "1.1.1.1"
	}
	a, e := netip.ParseAddr(o.Bootstrap)
	if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() {
		return nil, errors.New("invalid probe bootstrap")
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.StopTimeout == 0 {
		o.StopTimeout = time.Second
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute || o.StopTimeout <= 0 || o.StopTimeout > 10*time.Second {
		return nil, errors.New("invalid probe bounds")
	}
	if o.Concurrency == 0 {
		o.Concurrency = 2
	}
	if o.Concurrency < 1 || o.Concurrency > 8 {
		return nil, errors.New("invalid probe concurrency")
	}
	if o.TLSRoots != nil {
		o.TLSRoots = o.TLSRoots.Clone()
	}
	return &Prober{o, make(chan struct{}, o.Concurrency), sync.Mutex{}, map[string]Observation{}}, nil
}
func (p *Prober) Probe(ctx context.Context, ep endpoints.Endpoint, canary Canary) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	fail := func(code string) (Observation, error) { return p.record(ep.ID, 0, false, code), errors.New(code) }
	if ep.Validate() != nil || ep.ID == "" || !ep.Enabled {
		return fail("endpoint disabled or invalid")
	}
	u, err := url.Parse(canary.URL)
	if err != nil || len(canary.URL) > 8192 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fail("invalid canary URL")
	}
	if canary.ExpectedStatus == 0 {
		canary.ExpectedStatus = 204
	}
	if canary.ExpectedStatus < 200 || canary.ExpectedStatus > 299 {
		return fail("invalid canary status")
	}
	if canary.MaxBytes == 0 {
		canary.MaxBytes = 4096
	}
	if canary.MaxBytes < 1 || canary.MaxBytes > 64<<10 {
		return fail("invalid canary body bound")
	}
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return fail("probe canceled")
	}
	if privateParents(p.opts.Directory) != nil {
		return fail("probe directory unsafe")
	}
	dir, err := os.MkdirTemp(p.opts.Directory, "probe-")
	if err != nil {
		return fail("probe directory unavailable")
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail("private probe port unavailable")
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return fail("probe randomness unavailable")
	}
	password := hex.EncodeToString(secret)
	m := coreconfig.Model{SchemaVersion: 2, Instance: "health-probe", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, DefaultOutbound: ep.ID, DNS: coreconfig.DNS{Bootstrap: p.opts.Bootstrap, FakeIPRange: "198.18.0.0/15", CachePath: "/data/health-probe/cache.db"}}
	dnsPort := port + 1
	if dnsPort == 0 {
		dnsPort = 1
	}
	raw, err := coreconfig.GenerateWithOptions(m, coreconfig.Options{DNSPort: dnsPort, MixedPort: port})
	if err != nil {
		return fail("probe model invalid")
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		return fail("probe configuration invalid")
	}
	cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "health-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "health", "password": password}}}}
	cfg["route"].(map[string]any)["rules"] = []any{}
	delete(cfg, "experimental")
	raw, err = json.Marshal(cfg)
	if err != nil {
		return fail("probe configuration invalid")
	}
	path := filepath.Join(dir, "candidate.json")
	if os.WriteFile(path, raw, 0600) != nil {
		return fail("probe configuration unavailable")
	}
	if singbox.Check(ctx, p.opts.Binary, path) != nil {
		return fail("probe core validation failed")
	}
	cmd := exec.Command(p.opts.Binary, "run", "-c", path)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	processAttributes(cmd)
	if cmd.Start() != nil {
		return fail("probe process failed")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer stopProcess(cmd, done, p.opts.StopTimeout)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	for {
		select {
		case <-done:
			return fail("probe process exited")
		case <-ctx.Done():
			return fail("probe startup canceled")
		default:
		}
		conn, e := (&net.Dialer{Timeout: 20 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if e == nil {
			conn.Close()
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return fail("probe startup canceled")
		}
	}
	proxyURL := &url.URL{Scheme: "http", Host: address, User: url.UserPassword("health", password)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.opts.TLSRoots}, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("canary redirect refused") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fail("canary request invalid")
	}
	request.Header.Set("Cache-Control", "no-store")
	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return fail("canary request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, canary.MaxBytes+1))
	latency := time.Since(start)
	if err != nil || int64(len(body)) > canary.MaxBytes {
		return fail("canary body invalid")
	}
	if response.StatusCode != canary.ExpectedStatus {
		return fail("canary status mismatch")
	}
	if canary.ExpectedEgressIP.IsValid() {
		observed, e := netip.ParseAddr(strings.TrimSpace(string(body)))
		if e != nil || observed.Unmap() != canary.ExpectedEgressIP.Unmap() {
			return fail("canary egress mismatch")
		}
	}
	select {
	case <-done:
		return fail("probe exited before observation")
	case <-ctx.Done():
		return fail("probe canceled")
	default:
	}
	return p.record(ep.ID, latency, true, ""), nil
}
func (p *Prober) record(id string, latency time.Duration, available bool, code string) Observation {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.observations[id]; !exists && len(p.observations) >= 1024 {
		oldest := ""
		var before time.Time
		for key, value := range p.observations {
			if oldest == "" || value.CheckedAt.Before(before) {
				oldest = key
				before = value.CheckedAt
			}
		}
		delete(p.observations, oldest)
	}
	o := p.observations[id]
	o.EndpointID = id
	o.CheckedAt = time.Now().UTC()
	o.Available = available
	o.Failure = code
	if available {
		o.Latency = latency
		o.LastSuccess = o.CheckedAt
	} else {
		o.LastFailure = o.CheckedAt
	}
	p.observations[id] = o
	return o
}
func stopProcess(cmd *exec.Cmd, done <-chan struct{}, timeout time.Duration) {
	select {
	case <-done:
		return
	default:
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
}
func privateParents(path string) error {
	for {
		st, e := os.Lstat(path)
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink directory")
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		p := filepath.Dir(path)
		if p == path {
			return nil
		}
		path = p
	}
}
