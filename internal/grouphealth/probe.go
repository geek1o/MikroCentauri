// Package grouphealth observes each endpoint through an isolated, checked proxy
// process. It never probes by modifying the selection of the active dataplane.
package grouphealth

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/health"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/wireguard"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
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
	ResponseFormat   string
	ServerName       string
}
type Observation struct {
	coreconfig.Health
	EndpointID    string    `json:"endpoint_id"`
	CheckedAt     time.Time `json:"checked_at"`
	Failure       string    `json:"failure,omitempty"`
	EgressIP      string    `json:"egress_ip,omitempty"`
	FailureDetail string    `json:"failure_detail,omitempty"`
}
type ProbeOptions struct {
	Binary, Directory, Bootstrap string
	Timeout, StopTimeout         time.Duration
	TLSRoots                     *x509.CertPool
	Concurrency                  int
	FailureDiagnostics           bool
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
	if ep.Validate() != nil || ep.ID == "" || !ep.Enabled {
		return p.record(ep.ID, 0, false, "endpoint disabled or invalid"), errors.New("endpoint disabled or invalid")
	}
	m := coreconfig.Model{SchemaVersion: 2, Instance: "health-probe", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, DefaultOutbound: ep.ID, DNS: coreconfig.DNS{Bootstrap: p.opts.Bootstrap, FakeIPRange: "198.18.0.0/15", CachePath: "/data/health-probe/cache.db"}}
	return p.probeModel(ctx, ep.ID, m, canary)
}

// ProbeWireGuard requires a separately provisioned peer identity. Reusing an
// active key would make the remote WireGuard endpoint roam to the probe socket.
// The observation measures that dedicated peer's path to the same remote server;
// actual active-path authorization/readiness needs a separate current-path probe.
func (p *Prober) ProbeWireGuard(ctx context.Context, active, dedicated wireguard.Endpoint, canary Canary) (Observation, error) {
	identifier := active.ID
	if !dedicatedWGPeer(active, dedicated) {
		return p.record(identifier, 0, false, "dedicated WireGuard probe peer required"), errors.New("dedicated WireGuard probe peer required")
	}
	dedicated.ListenPort = 0
	dedicated.ID = ""
	ep, err := dedicated.Normalize()
	if err != nil {
		return p.record(identifier, 0, false, "WireGuard probe model invalid"), errors.New("WireGuard probe model invalid")
	}
	m := coreconfig.Model{SchemaVersion: 2, Instance: "health-probe", Mode: "socksify", WireGuard: []wireguard.Endpoint{ep}, DefaultOutbound: ep.ID, DNS: coreconfig.DNS{Bootstrap: p.opts.Bootstrap, FakeIPRange: "198.18.0.0/15", CachePath: "/data/health-probe/cache.db"}}
	return p.probeModel(ctx, identifier, m, canary)
}
func dedicatedWGPeer(active, probe wireguard.Endpoint) bool {
	if active.Validate() != nil || probe.Validate() != nil || active.ID == "" || probe.ID == "" || !active.Enabled || !probe.Enabled || active.PrivateKey == probe.PrivateKey || len(active.Peers) != len(probe.Peers) {
		return false
	}
	a, _ := base64.StdEncoding.DecodeString(active.PrivateKey)
	b, _ := base64.StdEncoding.DecodeString(probe.PrivateKey)
	ak, ae := ecdh.X25519().NewPrivateKey(a)
	bk, be := ecdh.X25519().NewPrivateKey(b)
	if ae != nil || be != nil || reflect.DeepEqual(ak.PublicKey().Bytes(), bk.PublicKey().Bytes()) {
		return false
	}
	addresses := map[netip.Addr]bool{}
	for _, raw := range active.Address {
		prefix, _ := netip.ParsePrefix(raw)
		addresses[prefix.Addr()] = true
	}
	for _, raw := range probe.Address {
		prefix, _ := netip.ParsePrefix(raw)
		if addresses[prefix.Addr()] {
			return false
		}
	}
	peers := map[string]wireguard.Peer{}
	for _, peer := range active.Peers {
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		sort.Strings(peer.AllowedIPs)
		peer.Address = strings.ToLower(peer.Address)
		peers[peer.PublicKey] = peer
	}
	for _, peer := range probe.Peers {
		peer.AllowedIPs = append([]string(nil), peer.AllowedIPs...)
		sort.Strings(peer.AllowedIPs)
		peer.Address = strings.ToLower(peer.Address)
		other, ok := peers[peer.PublicKey]
		if !ok || !reflect.DeepEqual(peer, other) {
			return false
		}
	}
	return true
}
func (p *Prober) probeModel(ctx context.Context, identifier string, m coreconfig.Model, canary Canary) (result Observation, probeErr error) {
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	var summary *errorSummary
	if p.opts.FailureDiagnostics {
		summary = &errorSummary{}
	}
	// This defer runs after the later child-stop defer has drained stderr.
	defer func() {
		if summary != nil && probeErr != nil {
			result.FailureDetail = summary.Code()
		}
	}()
	fail := func(code string) (Observation, error) {
		observed := p.record(identifier, 0, false, code)
		return observed, errors.New(code)
	}
	u, err := url.Parse(canary.URL)
	if err != nil || len(canary.URL) > 8192 || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fail("invalid canary URL")
	}
	if canary.ResponseFormat != "" && canary.ResponseFormat != health.CanaryRemoteIPJSON && canary.ResponseFormat != health.CanaryCloudflareTrace {
		return fail("invalid canary response format")
	}
	if canary.ResponseFormat == health.CanaryCloudflareTrace && u.Scheme != "https" {
		return fail("public trace requires verified HTTPS")
	}
	tlsConfig, canaryHost, err := health.CanaryTLS(canary.URL, canary.ServerName)
	if err != nil {
		return fail("invalid canary TLS profile")
	}
	tlsConfig.RootCAs = p.opts.TLSRoots
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
	var observed netip.Addr
	var latency time.Duration
	err = p.withProxyModel(ctx, m, summary, func(ctx context.Context, proxyURL *url.URL) error {
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: tlsConfig, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("canary redirect refused") }}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return errors.New("canary request invalid")
		}
		request.Header.Set("Cache-Control", "no-store")
		if canaryHost != "" {
			request.Host = canaryHost
		}
		start := time.Now()
		response, err := client.Do(request)
		if err != nil {
			return errors.New("canary request failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, canary.MaxBytes+1))
		latency = time.Since(start)
		if err != nil || int64(len(body)) > canary.MaxBytes {
			return errors.New("canary body invalid")
		}
		if response.StatusCode != canary.ExpectedStatus {
			return errors.New("canary status mismatch")
		}
		if canary.ResponseFormat != "" {
			observed, err = health.ParseCanaryIP(body, canary.ResponseFormat)
			if err != nil {
				return errors.New("canary peer response invalid")
			}
		} else if canary.ExpectedEgressIP.IsValid() {
			observed, err = netip.ParseAddr(strings.TrimSpace(string(body)))
			if err != nil {
				return errors.New("canary peer response invalid")
			}
		}
		if canary.ExpectedEgressIP.IsValid() && (!observed.IsValid() || observed.Unmap() != canary.ExpectedEgressIP.Unmap()) {
			return errors.New("canary egress mismatch")
		}
		return nil
	})
	if err != nil {
		return fail(err.Error())
	}
	return p.record(identifier, latency, true, "", observed), nil
}

// withProxyModel owns the complete lifetime of a temporary, loopback-only child.
// The operation cannot outlive the child or retain its private credentials.
func (p *Prober) withProxyModel(ctx context.Context, m coreconfig.Model, summary *errorSummary, operation func(context.Context, *url.URL) error) error {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return errors.New("probe canceled")
	}
	if privateParents(p.opts.Directory) != nil {
		return errors.New("probe directory unsafe")
	}
	dir, err := os.MkdirTemp(p.opts.Directory, "probe-")
	if err != nil {
		return errors.New("probe directory unavailable")
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.New("private probe port unavailable")
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return errors.New("probe randomness unavailable")
	}
	password := hex.EncodeToString(secret)
	dnsPort := port + 1
	if dnsPort == 0 {
		dnsPort = 1
	}
	raw, err := coreconfig.GenerateWithOptions(m, coreconfig.Options{DNSPort: dnsPort, MixedPort: port})
	if err != nil {
		return errors.New("probe model invalid")
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("probe configuration invalid")
	}
	cfg["inbounds"] = []any{map[string]any{"type": "mixed", "tag": "health-in", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"username": "health", "password": password}}}}
	cfg["route"].(map[string]any)["rules"] = []any{}
	delete(cfg, "experimental")
	raw, err = json.Marshal(cfg)
	if err != nil {
		return errors.New("probe configuration invalid")
	}
	path := filepath.Join(dir, "candidate.json")
	if os.WriteFile(path, raw, 0600) != nil {
		return errors.New("probe configuration unavailable")
	}
	if singbox.Check(ctx, p.opts.Binary, path) != nil {
		return errors.New("probe core validation failed")
	}
	cmd := exec.Command(p.opts.Binary, "run", "-c", path)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if summary != nil {
		cmd.Stderr = summary
		cmd.Stdout = summary
	}
	processAttributes(cmd)
	if cmd.Start() != nil {
		return errors.New("probe process failed")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer stopProcess(cmd, done, p.opts.StopTimeout)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	for {
		select {
		case <-done:
			return errors.New("probe process exited")
		case <-ctx.Done():
			return errors.New("probe startup canceled")
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
			return errors.New("probe startup canceled")
		}
	}
	proxyURL := &url.URL{Scheme: "http", Host: address, User: url.UserPassword("health", password)}
	if err := operation(ctx, proxyURL); err != nil {
		return err
	}
	select {
	case <-done:
		return errors.New("isolated proxy exited before operation completed")
	case <-ctx.Done():
		return errors.New("isolated proxy operation canceled")
	default:
		return nil
	}
}

// WithEndpointProxy runs a bounded operation through one enabled endpoint. It
// does not publish a health observation, apply policy or use a DIRECT fallback.
func (p *Prober) WithEndpointProxy(ctx context.Context, ep endpoints.Endpoint, operation func(context.Context, *url.URL) error) error {
	if operation == nil || ep.Validate() != nil || ep.ID == "" || !ep.Enabled {
		return errors.New("isolated proxy endpoint unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
	defer cancel()
	m := coreconfig.Model{SchemaVersion: 2, Instance: "health-probe", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, DefaultOutbound: ep.ID, DNS: coreconfig.DNS{Bootstrap: p.opts.Bootstrap, FakeIPRange: "198.18.0.0/15", CachePath: "/data/health-probe/cache.db"}}
	return p.withProxyModel(ctx, m, nil, operation)
}

func (p *Prober) record(id string, latency time.Duration, available bool, code string, egress ...netip.Addr) Observation {
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
	o.EgressIP = ""
	if available && len(egress) == 1 && egress[0].IsValid() {
		o.EgressIP = egress[0].Unmap().String()
	}
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
