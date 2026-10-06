package application

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
)

func testModel(t *testing.T) coreconfig.Model {
	t.Helper()
	endpoint, e := endpoints.ParseURI("trojan://private-password@example.org:443#proxy")
	if e != nil {
		t.Fatal(e)
	}
	return coreconfig.Model{SchemaVersion: 2, Instance: "api-native", Mode: "hybrid", Endpoints: []endpoints.Endpoint{endpoint}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{endpoint.ID}, Selected: endpoint.ID}}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "10.77.0.20", FakeIPRange: "198.19.0.0/16", CachePath: "/data/core/cache.db"}}
}
func testProfile() Profile {
	return Profile{Schema: 1, Directory: "/data/native", DNSListen: "172.30.0.2:5353", ReadinessListen: "172.30.0.2:9099", ObserverClient: "192.168.88.1", IngressInterface: "eth0", Table: 202, RulePriority: 1000, LocalRulePriority: 200, LANCIDR: "192.168.88.0/24", LANInterface: "bridge-lan", MappingChain: "mc-api-native-backup", MappingPlaceBefore: "*7", Capacity: 256, RealDNSAddress: "10.77.0.20:53", CanaryURL: "http://10.77.0.20:8080/ip", CanaryPeerIP: "10.77.0.1", Watchdog: routeros.WatchdogSpec{Instance: "api-native", Host: "172.30.0.2", Port: 9099, Interval: 2 * time.Second, Timeout: time.Second, SuccessThreshold: 3, LANLeaseCIDR: "192.168.88.0/24", Targets: []routeros.Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:api-native:route:fakeip", "disabled": "true", "dst-address": "198.19.0.0/16", "gateway": "172.30.0.2", "routing-table": "main"}}}}}
}
func TestProfileRejectsInvalidListenerAndTopologyInputs(t *testing.T) {
	m := testModel(t)
	if e := testProfile().Validate(m); e != nil {
		t.Fatal("fixture invalid", e)
	}
	cases := map[string]func(*Profile){
		"schema": func(p *Profile) { p.Schema = 2 }, "relative state": func(p *Profile) { p.Directory = "relative" }, "unclean state": func(p *Profile) { p.Directory = "/data/../native" },
		"public DNS": func(p *Profile) { p.DNSListen = "8.8.8.8:5353" }, "wildcard DNS": func(p *Profile) { p.DNSListen = "0.0.0.0:5353" }, "named DNS": func(p *Profile) { p.DNSListen = "localhost:5353" }, "IPv6 DNS": func(p *Profile) { p.DNSListen = "[::1]:5353" }, "internal allocator port": func(p *Profile) { p.DNSListen = "172.30.0.2:5354" },
		"shared socket": func(p *Profile) { p.DNSListen = p.ReadinessListen }, "different DNS IP": func(p *Profile) { p.DNSListen = "172.30.0.3:5353" }, "public observer": func(p *Profile) { p.ObserverClient = "8.8.8.8" }, "named observer": func(p *Profile) { p.ObserverClient = "router.local" },
		"resolver drift": func(p *Profile) { p.RealDNSAddress = "10.77.0.21:53" }, "resolver port": func(p *Profile) { p.RealDNSAddress = "10.77.0.20:5353" }, "noncanonical LAN": func(p *Profile) { p.LANCIDR = "192.168.88.1/24" }, "public LAN": func(p *Profile) { p.LANCIDR = "8.8.8.0/24" },
		"capacity zero": func(p *Profile) { p.Capacity = 0 }, "capacity bound": func(p *Profile) { p.Capacity = 4097 }, "watchdog instance": func(p *Profile) { p.Watchdog.Instance = "foreign" }, "watchdog host": func(p *Profile) { p.Watchdog.Host = "172.30.0.3" }, "watchdog port": func(p *Profile) { p.Watchdog.Port = 9098 }, "missing LAN lease": func(p *Profile) { p.Watchdog.LANLeaseCIDR = "" },
		"missing anchor": func(p *Profile) { p.MappingPlaceBefore = "" }, "named anchor": func(p *Profile) { p.MappingPlaceBefore = "rule-name" }, "numeric anchor": func(p *Profile) { p.MappingPlaceBefore = "7" }, "invalid anchor": func(p *Profile) { p.MappingPlaceBefore = "*G" },
		"bad ingress": func(p *Profile) { p.IngressInterface = "eth0;ip" }, "bad LAN interface": func(p *Profile) { p.LANInterface = "bridge;remove" }, "bad mapping chain": func(p *Profile) { p.MappingChain = "bad;chain" }, "reserved table": func(p *Profile) { p.Table = 254 }, "local priority collision": func(p *Profile) { p.LocalRulePriority = p.RulePriority }, "rule priority zero": func(p *Profile) { p.RulePriority = 0 },
		"canary invalid URL": func(p *Profile) { p.CanaryURL = "not-a-url" }, "canary named target": func(p *Profile) { p.CanaryURL = "http://probe.example/ip" }, "canary invalid peer": func(p *Profile) { p.CanaryPeerIP = "named-peer" }, "relative ruleset directory": func(p *Profile) { p.RuleSetDirectory = "relative" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := testProfile()
			mutate(&p)
			if p.Validate(m) == nil {
				t.Fatal("invalid operator profile accepted")
			}
		})
	}
}
func TestGuardedOwnerDeniesTopologyChangesBeforeAnyCoreMethod(t *testing.T) {
	m := testModel(t)
	calls := 0
	o := &guardedOwner{instance: m.Instance, pool: m.DNS.FakeIPRange, bootstrap: m.DNS.Bootstrap, profile: func(context.Context) error { calls++; return nil }}
	cases := map[string]func(*coreconfig.Model){"instance": func(m *coreconfig.Model) { m.Instance = "foreign" }, "mode": func(m *coreconfig.Model) { m.Mode = "full" }, "fakepool": func(m *coreconfig.Model) { m.DNS.FakeIPRange = "198.18.0.0/16" }, "bootstrap": func(m *coreconfig.Model) { m.DNS.Bootstrap = "10.77.0.21" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate, e := m.Clone()
			if e != nil {
				t.Fatal(e)
			}
			mutate(&candidate)
			if o.ValidateModel(context.Background(), 0, candidate) == nil {
				t.Fatal("validate allowed topology change")
			}
			if _, e := o.CandidateFingerprint(context.Background(), 0, candidate); e == nil {
				t.Fatal("plan allowed topology change")
			}
			if _, e := o.Apply(context.Background(), 0, nil, candidate); e == nil {
				t.Fatal("apply allowed topology change")
			}
			if _, e := o.ApplyPrepared(context.Background(), 0, nil, candidate, strings.Repeat("a", 64)); e == nil {
				t.Fatal("prepared apply allowed topology change")
			}
		})
	}
	if calls != 0 {
		t.Fatal("topology change reached profile/core")
	}
	if o.guard(context.Background(), m) != nil || calls != 1 {
		t.Fatal("valid topology denied")
	}
	sentinel := errors.New("native profile drift")
	o.profile = func(context.Context) error { return sentinel }
	if !errors.Is(o.ValidateModel(context.Background(), 0, m), sentinel) {
		t.Fatal("profile drift reached core validator")
	}
	if _, e := o.ApplyPrepared(context.Background(), 0, nil, m, strings.Repeat("a", 64)); !errors.Is(e, sentinel) {
		t.Fatal("profile drift reached core activation")
	}
}

type observerOwner struct{ *coreactivation.Transition }

func (*observerOwner) Status() coreactivation.TransitionStatus {
	return coreactivation.TransitionStatus{}
}
func TestNativeReadinessUsesSocketIdentityAndRejectsQuery(t *testing.T) {
	host, e := api.NewHost(api.HostOptions{Core: &observerOwner{}, Reconcile: func(context.Context) error { return nil }, Probe: func(context.Context) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	r := &Runtime{Host: host, Profile: testProfile()}
	for _, remote := range []string{"8.8.8.8:1234", "192.168.88.2:1234", "router.invalid", "[::ffff:192.168.88.1]:1234"} {
		request := httptest.NewRequest("GET", "http://native/", nil)
		request.RemoteAddr = remote
		request.Header.Set("X-Forwarded-For", r.Profile.ObserverClient)
		request.Header.Set("Forwarded", "for="+r.Profile.ObserverClient)
		w := httptest.NewRecorder()
		r.NativeHandler().ServeHTTP(w, request)
		if w.Code != 403 {
			t.Fatalf("forwarded identity bypass %s %d", remote, w.Code)
		}
	}
	for _, url := range []string{"http://native/?token=private", "http://native/api/v1/config"} {
		request := httptest.NewRequest("GET", url, nil)
		request.RemoteAddr = r.Profile.ObserverClient + ":1234"
		w := httptest.NewRecorder()
		r.NativeHandler().ServeHTTP(w, request)
		if w.Code != 404 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	request := httptest.NewRequest("GET", "http://native/", nil)
	request.RemoteAddr = r.Profile.ObserverClient + ":1234"
	w := httptest.NewRecorder()
	r.NativeHandler().ServeHTTP(w, request)
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"ready":false}` {
		t.Fatal("unproved host advertised ready", w.Code, w.Body.String())
	}
}

func TestStartupReadRetriesOnlyUnavailableTransport(t *testing.T) {
	calls := 0
	if err := startupRead(context.Background(), func(context.Context) error {
		calls++
		if calls == 1 {
			return routeros.ErrReadUnavailable
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
	permanent := errors.New("ownership denied")
	calls = 0
	if err := startupRead(context.Background(), func(context.Context) error { calls++; return permanent }); !errors.Is(err, permanent) || calls != 1 {
		t.Fatal(err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	err := startupRead(ctx, func(context.Context) error { calls++; cancel(); return routeros.ErrReadUnavailable })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal(err, calls)
	}
}
