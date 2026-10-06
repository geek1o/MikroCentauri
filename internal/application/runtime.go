// Package application composes the accepted core and backend owners. Installation
// of native steering is a separate controller transaction; startup verifies an
// already provisioned, immutable profile rather than guessing router topology.
package application

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/health"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/platform/linuxbarrier"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/realdns"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/supervisor"
)

// Profile is an operator-only 0600 input. It is never accepted over HTTP or
// included in backups. Kernel topology and native ownership remain fixed while
// API drafts edit policy. The pinned profile is intentionally narrower than the
// eventual release device matrix.
type Profile struct {
	Schema             int                   `json:"schema"`
	Directory          string                `json:"directory"`
	DNSListen          string                `json:"dns_listen"`
	ReadinessListen    string                `json:"readiness_listen"`
	ObserverClient     string                `json:"observer_client"`
	IngressInterface   string                `json:"ingress_interface"`
	Table              int                   `json:"table"`
	RulePriority       int                   `json:"rule_priority"`
	LocalRulePriority  int                   `json:"local_rule_priority"`
	LANCIDR            string                `json:"lan_cidr"`
	LANInterface       string                `json:"lan_interface"`
	MappingChain       string                `json:"mapping_chain"`
	MappingPlaceBefore string                `json:"mapping_place_before"`
	Capacity           uint32                `json:"capacity"`
	RealDNSAddress     string                `json:"real_dns_address"`
	CanaryURL          string                `json:"canary_url"`
	CanaryPeerIP       string                `json:"canary_peer_ip"`
	Watchdog           routeros.WatchdogSpec `json:"watchdog"`
	RuleSetDirectory   string                `json:"ruleset_directory,omitempty"`
}

type Runtime struct {
	*api.Host
	DNS              dnsgate.Handler
	Profile          Profile
	ledger           *fakeip.Publisher
	store            *namespace.Store
	diagnosticProbes map[string]func(context.Context) error
	binary           string
}

type guardedOwner struct {
	*coreactivation.Transition
	profile                   func(context.Context) error
	instance, pool, bootstrap string
}

func (o *guardedOwner) guard(ctx context.Context, m coreconfig.Model) error {
	if m.Instance != o.instance || m.Mode != "hybrid" || m.DNS.FakeIPRange != o.pool || m.DNS.Bootstrap != o.bootstrap {
		return errors.New("draft changes operator topology")
	}
	return o.profile(ctx)
}
func (o *guardedOwner) ValidateModel(ctx context.Context, rev uint64, m coreconfig.Model) error {
	if err := o.guard(ctx, m); err != nil {
		return err
	}
	return o.Transition.ValidateModel(ctx, rev, m)
}
func (o *guardedOwner) CandidateFingerprint(ctx context.Context, rev uint64, m coreconfig.Model) (string, error) {
	if err := o.guard(ctx, m); err != nil {
		return "", err
	}
	return o.Transition.CandidateFingerprint(ctx, rev, m)
}
func (o *guardedOwner) Apply(ctx context.Context, rev uint64, active []string, m coreconfig.Model) (namespace.Snapshot, error) {
	if err := o.guard(ctx, m); err != nil {
		return namespace.Snapshot{}, err
	}
	return o.Transition.Apply(ctx, rev, active, m)
}
func (o *guardedOwner) ApplyPrepared(ctx context.Context, rev uint64, active []string, m coreconfig.Model, fp string) (namespace.Snapshot, error) {
	if err := o.guard(ctx, m); err != nil {
		return namespace.Snapshot{}, err
	}
	return o.Transition.ApplyPrepared(ctx, rev, active, m, fp)
}

func (o *guardedOwner) Recover(ctx context.Context) (namespace.Snapshot, error) {
	m, e := o.CurrentModel()
	if e != nil {
		return namespace.Snapshot{}, e
	}
	if e = o.guard(ctx, m); e != nil {
		return namespace.Snapshot{}, e
	}
	return o.Transition.Recover(ctx)
}

func privateAddress(s string) (netip.Addr, int, error) {
	host, port, e := net.SplitHostPort(s)
	if e != nil {
		return netip.Addr{}, 0, errors.New("literal private address required")
	}
	ip, e := netip.ParseAddr(host)
	n, err := strconv.Atoi(port)
	if e != nil || err != nil || !ip.Is4() || (!ip.IsPrivate() && !ip.IsLoopback()) || n < 1 || n > 65535 {
		return netip.Addr{}, 0, errors.New("literal private address required")
	}
	return ip, n, nil
}

var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func (p Profile) Validate(m coreconfig.Model) error {
	if !ifacePattern.MatchString(p.IngressInterface) || !ifacePattern.MatchString(p.LANInterface) || p.IngressInterface == "mc-tun" || p.Table < 1 || p.Table >= 253 || p.RulePriority < 1 || p.RulePriority >= 32766 || p.LocalRulePriority < 0 || p.LocalRulePriority >= p.RulePriority {
		return errors.New("invalid kernel topology")
	}
	if p.RuleSetDirectory != "" && (!filepath.IsAbs(p.RuleSetDirectory) || filepath.Clean(p.RuleSetDirectory) != p.RuleSetDirectory) {
		return errors.New("invalid operator rule-set directory")
	}
	u, e := url.Parse(p.CanaryURL)
	if e != nil {
		return errors.New("invalid independent canary")
	}
	canary, e := netip.ParseAddr(u.Hostname())
	if e != nil || !canary.Is4() || canary.IsUnspecified() || canary.IsMulticast() || canary.IsLoopback() {
		return errors.New("independent canary requires literal unicast IPv4")
	}
	if _, e := health.NewHTTPProbe(health.HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: p.CanaryURL, ExpectedPeerIP: p.CanaryPeerIP, Timeout: 2 * time.Second}); e != nil {
		return e
	}

	dns, dp, e := privateAddress(p.DNSListen)
	if e != nil {
		return e
	}
	ready, rp, e := privateAddress(p.ReadinessListen)
	if e != nil {
		return e
	}
	observer, e := netip.ParseAddr(p.ObserverClient)
	if e != nil || !observer.Is4() || (!observer.IsPrivate() && !observer.IsLoopback()) || observer.IsUnspecified() {
		return errors.New("private native observer client required")
	}
	real, port, e := net.SplitHostPort(p.RealDNSAddress)
	if e != nil || port != "53" || real != m.DNS.Bootstrap {
		return errors.New("DNS resolver must match operator model bootstrap")
	}
	lan, e := netip.ParsePrefix(p.LANCIDR)
	if e != nil || !lan.Addr().Is4() || !lan.Addr().IsPrivate() || lan != lan.Masked() {
		return errors.New("canonical private LAN required")
	}
	if !regexp.MustCompile(`^\*[A-Fa-f0-9]+$`).MatchString(p.MappingPlaceBefore) {
		return errors.New("stable static mapping placement anchor required")
	}
	if p.Schema != 1 || p.Directory == "" || !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || p.Capacity < 1 || p.Capacity > 4096 || m.Mode != "hybrid" || p.DNSListen == p.ReadinessListen || dp == 5354 || dp == 2080 || rp == 5354 || rp == 2080 || dns != ready || p.Watchdog.Instance != m.Instance || p.Watchdog.Host != ready.String() || p.Watchdog.Port != rp || p.Watchdog.LANLeaseCIDR != p.LANCIDR {
		return errors.New("inconsistent runtime profile")
	}
	watch, e := routeros.DesiredWatchdog(p.Watchdog)
	if e != nil {
		return e
	}
	if _, e := routeros.DesiredMappingJump(routeros.MappingBackendOptions{Instance: m.Instance, Chain: p.MappingChain, LANCIDR: p.LANCIDR, LANInterface: p.LANInterface, FakeIPRange: m.DNS.FakeIPRange, UpLeaseList: "mc-" + m.Instance + "-up-lease", JumpComment: "mikrocentauri:" + m.Instance + ":nat:backup-jump", JumpPlaceBefore: p.MappingPlaceBefore, Observer: watch}); e != nil {
		return e
	}
	return m.Validate()
}

func New(ctx context.Context, p Profile, m coreconfig.Model, c *routeros.Client, binary string) (*Runtime, error) {
	if c == nil || binary == "" {
		return nil, errors.New("native client and pinned binary required")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("native runtime requires Linux container")
	}
	if e := p.Validate(m); e != nil {
		return nil, e
	}
	var caps routeros.Capabilities
	e := startupRead(ctx, func(ctx context.Context) error {
		var err error
		caps, err = c.Capabilities(ctx)
		return err
	})
	if e != nil {
		return nil, errors.Join(errors.New("native capability read unavailable"), e)
	}
	if (caps.Version != "7.24.5" && caps.Version != "7.24.5 (stable)") || caps.Architecture != "x86_64" || !strings.HasPrefix(caps.Board, "CHR ") {
		return nil, errors.New("runtime profile is accepted only on CHR 7.24.5 x86_64")
	}
	dir, e := api.PrivateDirectory(p.Directory)
	if e != nil {
		return nil, e
	}
	watch, e := routeros.DesiredWatchdog(p.Watchdog)
	if e != nil {
		return nil, e
	}
	backend, e := routeros.NewMappingBackend(c, routeros.MappingBackendOptions{Instance: m.Instance, Chain: p.MappingChain, LANCIDR: p.LANCIDR, LANInterface: p.LANInterface, FakeIPRange: m.DNS.FakeIPRange, UpLeaseList: "mc-" + m.Instance + "-up-lease", JumpComment: "mikrocentauri:" + m.Instance + ":nat:backup-jump", JumpPlaceBefore: p.MappingPlaceBefore, Observer: watch})
	if e != nil {
		return nil, e
	}
	if e = startupRead(ctx, backend.VerifyProfile); e != nil {
		return nil, errors.New("native profile requires provisioning or repair")
	}
	native, e := routeros.NewCoreNativeBarrier(c, routeros.CoreNativeBarrierOptions{Instance: m.Instance, Observer: watch, ReservedLists: []routeros.CoreReservedList{{List: "mc-" + m.Instance + "-watch-count", Comment: "mikrocentauri:" + m.Instance + ":watchdog-counter"}, {List: "mc-" + m.Instance + "-up-lease", Comment: "mikrocentauri:" + m.Instance + ":lease:up", Address: p.LANCIDR}}})
	if e != nil {
		return nil, e
	}
	pc := health.HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: p.CanaryURL, ExpectedPeerIP: p.CanaryPeerIP, Timeout: 2 * time.Second}
	barrier, e := linuxbarrier.New(linuxbarrier.Options{Interface: p.IngressInterface, TUN: "mc-tun", Table: p.Table, RulePriority: p.RulePriority, LocalRulePriority: p.LocalRulePriority, TUNPrefix: netip.MustParsePrefix("172.31.255.1/30"), Native: native, Canary: pc, IndependentCanary: true})
	if e != nil {
		return nil, e
	}
	resolver, e := realdns.New(realdns.Config{Address: p.RealDNSAddress})
	if e != nil {
		return nil, e
	}
	prefix, e := netip.ParsePrefix(m.DNS.FakeIPRange)
	if e != nil {
		return nil, e
	}
	ledger, e := fakeip.New(fakeip.Config{Directory: filepath.Join(dir, "publication"), Prefix: prefix, Capacity: p.Capacity}, resolver, backend)
	if e != nil {
		return nil, e
	}
	store, e := namespace.New(namespace.Config{Directory: filepath.Join(dir, "namespace"), Initial: m.DNS.SelectedDomains, Capacity: p.Capacity})
	if e != nil {
		ledger.Close()
		return nil, e
	}
	alloc, e := dnsgate.NewAllocator("127.0.0.1:5354")
	if e != nil {
		store.Close()
		ledger.Close()
		return nil, e
	}
	var resolve func(context.Context, coreconfig.Model) ([]rulesets.Artifact, error)
	if p.RuleSetDirectory != "" {
		manager, err := rulesets.New(p.RuleSetDirectory, binary, rulesets.Policy{})
		if err != nil {
			store.Close()
			ledger.Close()
			return nil, err
		}
		resolve = func(ctx context.Context, m coreconfig.Model) ([]rulesets.Artifact, error) {
			a := []rulesets.Artifact{}
			for _, ref := range m.RuleSets {
				if e := ctx.Err(); e != nil {
					return nil, e
				}
				v, e := manager.Load(ref.ID)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			return a, nil
		}
	}
	t, e := coreactivation.NewTransition(coreactivation.TransitionOptions{Directory: filepath.Join(dir, "transitions"), Store: store, Model: m, ResolveRuleSets: resolve, Activation: coreactivation.Options{Ledger: ledger, Engine: alloc, Barrier: barrier, Prefix: prefix, Capacity: p.Capacity, Ports: coreconfig.Options{DNSPort: 5354, MixedPort: 2080}, RealDNSAddress: p.RealDNSAddress, Timeout: 25 * time.Second}, Process: supervisor.Options{Binary: binary, Directory: filepath.Join(dir, "process"), ReadyTimeout: 25 * time.Second, StopTimeout: 2 * time.Second}})
	if e != nil {
		store.Close()
		ledger.Close()
		return nil, e
	}
	owner := &guardedOwner{Transition: t, profile: backend.VerifyProfile, instance: m.Instance, pool: m.DNS.FakeIPRange, bootstrap: m.DNS.Bootstrap}
	probe, e := health.NewHTTPProbe(pc)
	if e != nil {
		t.Close(ctx)
		store.Close()
		ledger.Close()
		return nil, e
	}
	h, e := api.NewHost(api.HostOptions{Core: owner, Reconcile: func(ctx context.Context) error {
		if e := backend.VerifyProfile(ctx); e != nil {
			return e
		}
		return ledger.Reconcile(ctx)
	}, Probe: probe.Check})
	if e != nil {
		t.Close(ctx)
		store.Close()
		ledger.Close()
		return nil, e
	}
	return &Runtime{Host: h, DNS: t.Handler(), Profile: p, ledger: ledger, store: store, binary: binary, diagnosticProbes: map[string]func(context.Context) error{"proxy": probe.Check, "watchdog": backend.VerifyProfile, "routing": func(ctx context.Context) error {
		if e := barrier.InspectActive(ctx); e != nil {
			return e
		}
		return backend.VerifyProfile(ctx)
	}}}, nil
}
func (r *Runtime) Close(ctx context.Context) error {
	e := r.Host.Close(ctx)
	r.store.Close()
	r.ledger.Close()
	return e
}

// NativeHandler exposes only readiness to the pinned router's actual socket IP.
// Forwarded headers cannot grant access.
func (r *Runtime) NativeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		host, _, e := net.SplitHostPort(q.RemoteAddr)
		if e != nil || host != r.Profile.ObserverClient {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		r.Host.ReadinessHandler().ServeHTTP(w, q)
	})
}

// Retry only transport-unavailable reads before opening any durable owner.
// Readiness stays DOWN; authentication, TLS trust, syntax and ownership errors
// are not retried and no native mutation is issued here.
func startupRead(ctx context.Context, read func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := read(ctx)
		if !errors.Is(err, routeros.ErrReadUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
