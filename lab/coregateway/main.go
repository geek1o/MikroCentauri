// Disposable CHR fixture for the production core transition owner. Its public
// credentials and HTTP controls are confined to the isolated 172.30.0.2 veth.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/health"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/platform/linuxbarrier"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/realdns"
	"mikrocentauri.local/core/internal/supervisor"
)

const base = "/data/core-v3"

var initial = []string{"selected.test", "second.test", "third.test"}

func model(active []string) (coreconfig.Model, error) {
	ep, e := endpoints.ParseURI("vless://bf000d23-0752-40b4-affe-68f7707a9661@10.77.0.10:8443?security=none&type=tcp#Lab-only")
	if e != nil {
		return coreconfig.Model{}, e
	}
	ep.Enabled = true
	m := coreconfig.Model{SchemaVersion: 2, Instance: "corelab", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{ep.ID}, Selected: ep.ID}}, DefaultOutbound: "direct", SourceDirect: []string{"192.168.88.30/32"}, SourceProxy: []coreconfig.SourcePolicy{{CIDRs: []string{"192.168.88.20/32"}, Outbound: "proxy"}}, DNS: coreconfig.DNS{Bootstrap: "10.77.0.20", FakeIPRange: "198.19.0.0/16", SelectedDomains: active, CachePath: base + "/cache.db"}, Rules: []coreconfig.Rule{{ID: "independent-canary", DestinationCIDRs: []string{"10.77.0.10/32"}, Outbound: "proxy"}}}
	if len(active) > 0 {
		m.Rules = append(m.Rules, coreconfig.Rule{ID: "selected-domains", Domains: active, Outbound: "proxy"})
	}
	return m, m.Validate()
}

type faultBarrier struct {
	coreactivation.Barrier
	mu       sync.Mutex
	path     string
	admitted func() bool
}

func (b *faultBarrier) arm(f string) error {
	if f != "after-verify" && f != "before-release" {
		return errors.New("invalid fault")
	}
	return config.WriteAtomic(b.path, []byte(f))
}
func (b *faultBarrier) fire(f string, code int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, e := os.ReadFile(b.path)
	if e != nil || string(data) != f {
		return
	}
	if os.Remove(b.path) != nil {
		return
	}
	d, e := os.Open(filepath.Dir(b.path))
	if e != nil {
		return
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return
	}
	os.Exit(code)
}
func (b *faultBarrier) Quarantine(ctx context.Context) error {
	err := b.Barrier.Quarantine(ctx)
	if err != nil {
		log.Printf("corelab forwarding quarantine: %v", err)
		out, _ := exec.CommandContext(ctx, "/sbin/ip", "rule", "show").Output()
		log.Printf("corelab kernel policy readback: %q", string(out))
		for _, args := range [][]string{{"-o", "-4", "addr", "show"}, {"route", "show", "table", "local"}, {"route", "show", "table", "main"}, {"route", "get", "172.30.0.1"}, {"neigh", "show"}} {
			out, _ = exec.CommandContext(ctx, "/sbin/ip", args...).Output()
			log.Printf("corelab kernel %v: %q", args, string(out))
		}
	}
	return err
}
func (b *faultBarrier) Verify(ctx context.Context, m coreconfig.Model) error {
	if e := b.Barrier.Verify(ctx, m); e != nil {
		return e
	}
	if b.admitted == nil || b.admitted() {
		b.fire("after-verify", 77)
	}
	return nil
}
func (b *faultBarrier) Release(ctx context.Context) error {
	b.fire("before-release", 78)
	return b.Barrier.Release(ctx)
}

type lab struct {
	mu      sync.Mutex
	t       *coreactivation.Transition
	pub     *fakeip.Publisher
	probe   *health.HTTPProbe
	barrier *faultBarrier
	ready   atomic.Bool
	paused  bool
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter) {
	respond(w, 503, map[string]string{"error": "core transition failed"})
}
func (l *lab) recover(ctx context.Context) (namespace.Snapshot, error) {
	l.ready.Store(false)
	s, e := l.t.Recover(ctx)
	if e == nil {
		e = l.probe.Check(ctx)
	}
	if e == nil {
		l.ready.Store(true)
		l.paused = false
	} else {
		_ = l.t.Hold(ctx)
	}
	return s, e
}
func (l *lab) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" && r.Method == "GET" {
		if l.ready.Load() && l.t.Status().Ready {
			respond(w, 200, map[string]bool{"ready": true})
		} else {
			respond(w, 503, map[string]bool{"ready": false})
		}
		return
	}
	if r.URL.Path == "/status" && r.Method == "GET" {
		s := l.t.Status()
		respond(w, 200, map[string]any{"ready": l.ready.Load() && s.Ready, "namespace": s.Namespace, "process": s.Process, "admission": s.Traffic.Admission})
		return
	}
	if r.Method != "POST" {
		respond(w, 404, map[string]string{"error": "unknown control"})
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	switch r.URL.Path {
	case "/control/namespace":
		var req struct {
			Revision uint64   `json:"revision"`
			Active   []string `json:"active"`
			Fault    string   `json:"fault,omitempty"`
		}
		d := json.NewDecoder(io.LimitReader(r.Body, 8193))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
			respond(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if len(req.Active) > 32 {
			respond(w, 400, map[string]string{"error": "capacity exceeded"})
			return
		}
		active := make([]string, len(req.Active))
		for i, n := range req.Active {
			c, e := fakeip.CanonicalDomain(n)
			if e != nil {
				respond(w, 400, map[string]string{"error": "invalid domain"})
				return
			}
			active[i] = c
		}
		m, e := model(active)
		if e != nil {
			respond(w, 400, map[string]string{"error": "invalid model"})
			return
		}
		if req.Fault != "" {
			if e = l.barrier.arm(req.Fault); e != nil {
				respond(w, 400, map[string]string{"error": "invalid fault"})
				return
			}
		}
		wasReady := l.ready.Load()
		l.ready.Store(false)
		s, e := l.t.Apply(ctx, req.Revision, active, m)
		if e != nil {
			os.Remove(l.barrier.path)
			l.ready.Store(wasReady && l.t.Status().Ready)
			failure(w)
			return
		}
		if l.probe.Check(ctx) != nil {
			_ = l.t.Hold(ctx)
			failure(w)
			return
		}
		l.ready.Store(true)
		l.paused = false
		respond(w, 200, s)
	case "/control/recover":
		s, e := l.recover(ctx)
		if e != nil {
			failure(w)
		} else {
			respond(w, 200, s)
		}
	case "/control/crash":
		l.ready.Store(false)
		l.paused = true
		s := l.t.Status()
		if s.Process.PID > 0 {
			_ = syscall.Kill(s.Process.PID, syscall.SIGKILL)
		}
		e := l.t.Hold(ctx)
		if e != nil {
			failure(w)
		} else {
			respond(w, 200, map[string]bool{"ready": false})
		}
	default:
		respond(w, 404, map[string]string{"error": "unknown control"})
	}
}

type diagnosticTransport struct{}

func (diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		log.Printf("corelab native transport: %v", err)
	}
	return resp, err
}
func run() error {
	if os.Getenv("MC_CORE_LAB") != "1" {
		return errors.New("explicit disposable fixture flag required")
	}
	syscall.Umask(0077)
	if e := os.MkdirAll(base, 0700); e != nil {
		return fmt.Errorf("private-directory: %w", e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	client, e := routeros.NewLabClient("http://172.30.0.1/rest", "mc-lab", "DisposableLabOnly-2026", &http.Client{Transport: diagnosticTransport{}, Timeout: 3 * time.Second})
	if e != nil {
		return fmt.Errorf("rest-client: %w", e)
	}
	native, e := routeros.NewLabCoreNativeBarrier(client, routeros.CoreNativeBarrierOptions{Instance: "lab", Observer: routeros.Object{Path: "tool/netwatch", Fields: map[string]string{"comment": "mikrocentauri:lab:netwatch:readiness", "host": "172.30.0.2", "port": "9099", "type": "http-get", "http-codes": "200"}}, ReservedLists: []routeros.CoreReservedList{{List: "mc-lab-up-lease", Comment: "mikrocentauri:lab:lease:up", Address: "192.168.88.0/24"}}})
	if e != nil {
		return fmt.Errorf("native-barrier: %w", e)
	}
	pc := health.HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://10.77.0.10:8080/", ExpectedPeerIP: "10.77.0.10", Timeout: 2 * time.Second}
	b, e := linuxbarrier.New(linuxbarrier.Options{Interface: "mc-probe", TUN: "mc-tun", Table: 100, RulePriority: 10000, LocalRulePriority: 200, TUNPrefix: netip.MustParsePrefix("172.31.255.1/30"), Native: native, Canary: pc, IndependentCanary: true})
	if e != nil {
		return fmt.Errorf("linux-barrier: %w", e)
	}
	fb := &faultBarrier{Barrier: b, path: base + "/fault"}
	backend, e := routeros.NewLabLeaseMappingBackend(client)
	if e != nil {
		return fmt.Errorf("mapping-backend: %w", e)
	}
	resolver, e := realdns.New(realdns.Config{Address: "10.77.0.20:53"})
	if e != nil {
		return fmt.Errorf("real-dns: %w", e)
	}
	pub, e := fakeip.New(fakeip.Config{Directory: base + "/publication", Prefix: netip.MustParsePrefix("198.19.0.0/16"), Capacity: 32}, resolver, backend)
	if e != nil {
		return fmt.Errorf("publisher: %w", e)
	}
	defer pub.Close()
	store, e := namespace.New(namespace.Config{Directory: base + "/namespace", Initial: initial, Capacity: 32})
	if e != nil {
		return fmt.Errorf("namespace: %w", e)
	}
	defer store.Close()
	alloc, e := dnsgate.NewAllocator("127.0.0.1:5354")
	if e != nil {
		return fmt.Errorf("allocator: %w", e)
	}
	m, e := model(initial)
	if e != nil {
		return fmt.Errorf("model: %w", e)
	}
	t, e := coreactivation.NewTransition(coreactivation.TransitionOptions{Directory: base + "/transitions", Store: store, Model: m, Activation: coreactivation.Options{Ledger: pub, Engine: alloc, Barrier: fb, Prefix: netip.MustParsePrefix("198.19.0.0/16"), Capacity: 32, Ports: coreconfig.Options{DNSPort: 5354, MixedPort: 2080}, RealDNSAddress: "10.77.0.20:53", Timeout: 25 * time.Second}, Process: supervisor.Options{Binary: "/bin/sing-box", Directory: base + "/process", ReadyTimeout: 25 * time.Second, StopTimeout: 2 * time.Second}})
	if e != nil {
		return fmt.Errorf("transition: %w", e)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = t.Close(c)
	}()
	probe, e := health.NewHTTPProbe(pc)
	if e != nil {
		return fmt.Errorf("probe: %w", e)
	}
	fb.admitted = func() bool { return t.Status().Traffic.Admission.Admitted }
	l := &lab{t: t, pub: pub, probe: probe, barrier: fb}
	srv := &http.Server{Addr: "172.30.0.2:9099", Handler: http.HandlerFunc(l.serve), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 5 * time.Second}
	go func() {
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			cancel()
		}
	}()
	defer srv.Close()
	go func() {
		if dnsgate.Serve(ctx, "172.30.0.2:5353", t.Handler()) != nil {
			cancel()
		}
	}()
	// Quarantine ingress before enabling Linux forwarding or recovering intent.
	c, cc := context.WithTimeout(ctx, 30*time.Second)
	e = t.Hold(c)
	cc()
	if e != nil {
		return fmt.Errorf("initial-hold: %w", e)
	}
	if e = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); e != nil {
		return fmt.Errorf("forwarding: %w", e)
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		l.mu.Lock()
		c, cc = context.WithTimeout(ctx, 35*time.Second)
		if !l.paused {
			if !l.ready.Load() {
				_, _ = l.recover(c)
			} else {
				e = pub.Reconcile(c)
				if e == nil {
					e = t.Check(c)
				}
				if e == nil {
					e = probe.Check(c)
				}
				if e != nil {
					l.ready.Store(false)
					_ = t.Hold(c)
				}
			}
		}
		cc()
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func main() {
	if err := run(); err != nil {
		log.Printf("core lab startup or lifecycle failed: %v", err)
		os.Exit(1)
	}
}
