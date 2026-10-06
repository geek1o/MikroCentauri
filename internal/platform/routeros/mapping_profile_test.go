//go:build linux || darwin

package routeros

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

func profileFixture(t *testing.T) (*MappingBackend, *mockRouter, MappingBackendOptions) {
	t.Helper()
	spec := testWatchdogSpec()
	spec.LANLeaseCIDR = "192.168.88.0/24"
	bundle, err := WatchdogBundle(spec)
	if err != nil {
		t.Fatal(err)
	}
	opts := MappingBackendOptions{Instance: spec.Instance, Chain: "mc-phase2-backup", LANCIDR: spec.LANLeaseCIDR, LANInterface: "bridge-lan", FakeIPRange: "198.19.0.0/16", UpLeaseList: "mc-phase2-up-lease", JumpComment: "mikrocentauri:phase2:nat:backup-jump", Observer: bundle[0]}
	jump, err := DesiredMappingJump(opts)
	if err != nil {
		t.Fatal(err)
	}
	objects := append([]Object{}, spec.Targets...)
	for _, o := range bundle {
		o = copyWatchObject(o)
		o.Fields["disabled"] = "false"
		objects = append(objects, o)
	}
	objects = append(objects, jump)
	for i := range objects {
		objects[i].ID = "*" + string(rune('A'+i))
		if objects[i].Path == "tool/netwatch" {
			objects[i].Fields["status"] = "down"
		}
	}
	m := &mockRouter{objects: objects, next: 100}
	server := httptest.NewTLSServer(m)
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+"/rest", "lab", "test-password", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewMappingBackend(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	return b, m, opts
}
func TestProductionMappingProfileHTTPSAndImmutableTargets(t *testing.T) {
	b, m, opts := profileFixture(t)
	ctx := context.Background()
	if err := b.VerifyProfile(ctx); err != nil {
		t.Fatal(err)
	}
	value := fakeip.Mapping{Domain: "one.test", Fake: netip.MustParseAddr("198.19.0.2"), Real: netip.MustParseAddr("10.77.0.20")}
	if err := b.Ensure(ctx, value); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(ctx, value); err != nil {
		t.Fatal(err)
	}
	if err := b.Ensure(ctx, value); err != nil || m.mutations != 1 {
		t.Fatal("publication not idempotent", err)
	}
	after := value
	after.Real = netip.MustParseAddr("10.77.0.21")
	if err := b.Update(ctx, value, after); err != nil {
		t.Fatal(err)
	}
	if err := b.Update(ctx, value, after); err != nil || m.mutations != 2 {
		t.Fatal("transition wrote twice", err)
	}
	if err := b.Ensure(ctx, value); err == nil {
		t.Fatal("alias reassigned without journaled pair")
	}
	for _, object := range m.objects {
		if object.Path == "ip/firewall/nat" && object.Fields["chain"] == opts.Chain && (!Owned(opts.Instance, object) || object.Fields["disabled"] != "false") {
			t.Fatal("unowned or switched map")
		}
	}
	plain, _ := NewLabClient("http://127.0.0.1/rest", "lab", "test-password", nil)
	if _, err := NewMappingBackend(plain, opts); err == nil {
		t.Fatal("plaintext production transport")
	}
}
func TestProductionMappingProfileRefusesForeignAndMalformedAuthority(t *testing.T) {
	for _, kind := range []string{"static-lease", "foreign-lease", "duplicate-lease", "wrong-lease", "forever-lease", "foreign-chain", "duplicate-alias", "foreign-jump", "disabled-guard", "tampered-guard", "tampered-observer", "unscoped-jump"} {
		t.Run(kind, func(t *testing.T) {
			b, m, opts := profileFixture(t)
			value := fakeip.Mapping{Domain: "one.test", Fake: netip.MustParseAddr("198.19.0.2"), Real: netip.MustParseAddr("10.77.0.20")}
			lease := Object{Path: "ip/firewall/address-list", ID: "*LEASE", Fields: map[string]string{"list": opts.UpLeaseList, "comment": "mikrocentauri:phase2:lease:up", "address": opts.LANCIDR, "dynamic": "true", "timeout": "5s"}}
			switch kind {
			case "static-lease":
				lease.Fields["dynamic"] = "false"
				m.objects = append(m.objects, lease)
			case "foreign-lease":
				lease.Fields["comment"] = "user"
				m.objects = append(m.objects, lease)
			case "duplicate-lease":
				m.objects = append(m.objects, lease, lease)
			case "wrong-lease":
				lease.Fields["address"] = "192.168.0.0/16"
				m.objects = append(m.objects, lease)
			case "forever-lease":
				lease.Fields["timeout"] = "none-dynamic"
				m.objects = append(m.objects, lease)
			case "foreign-chain":
				m.objects = append(m.objects, Object{Path: "ip/firewall/nat", ID: "*FOREIGN", Fields: map[string]string{"chain": opts.Chain, "action": "accept"}})
			case "foreign-jump":
				m.objects = append(m.objects, Object{Path: "ip/firewall/nat", ID: "*FOREIGN", Fields: map[string]string{"chain": "dstnat", "action": "jump", "jump-target": opts.Chain, "comment": "user"}})
			case "duplicate-alias":
				fields, _ := b.fields(value)
				m.objects = append(m.objects, Object{Path: "ip/firewall/nat", ID: "*M1", Fields: fields}, Object{Path: "ip/firewall/nat", ID: "*M2", Fields: fields})
			case "disabled-guard", "tampered-guard":
				for i := range m.objects {
					if m.objects[i].Path == "system/scheduler" {
						if kind == "disabled-guard" {
							m.objects[i].Fields["disabled"] = "true"
						} else {
							m.objects[i].Fields["on-event"] += " /system/reboot"
						}
					}
				}
			case "tampered-observer":
				for i := range m.objects {
					if m.objects[i].Path == "tool/netwatch" {
						m.objects[i].Fields["host"] = "172.30.0.3"
					}
				}
			case "unscoped-jump":
				for i := range m.objects {
					if m.objects[i].Fields["comment"] == opts.JumpComment {
						delete(m.objects[i].Fields, "src-address-list")
					}
				}
			}
			if b.VerifyProfile(context.Background()) == nil || b.Ensure(context.Background(), value) == nil || m.mutations != 0 {
				t.Fatal("unsafe profile admitted or mutated")
			}
		})
	}
}
func TestNativeLANLeaseBarrierCounterValidationIsIndependent(t *testing.T) {
	b, m, opts := profileFixture(t)
	counter := Object{Path: "ip/firewall/address-list", ID: "*C", Fields: map[string]string{"list": "mc-phase2-watch-count", "comment": "mikrocentauri:phase2:watchdog-counter", "address": "127.0.0.3", "dynamic": "true", "timeout": "5s"}}
	lease := Object{Path: "ip/firewall/address-list", ID: "*L", Fields: map[string]string{"list": opts.UpLeaseList, "comment": "mikrocentauri:phase2:lease:up", "address": opts.LANCIDR, "dynamic": "true", "timeout": "5s"}}
	m.objects = append(m.objects, counter, lease)
	if err := b.VerifyProfile(context.Background()); err != nil {
		t.Fatal("valid LAN prefix mistaken for counter address", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if b.barrier.Quarantine(ctx) == nil {
		t.Fatal("live lease admitted as revoked")
	}
	m.objects = m.objects[:len(m.objects)-2]
	if err := b.barrier.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad := b.barrier.options
	bad.ReservedLists = bad.ReservedLists[:1]
	if _, err := NewCoreNativeBarrier(b.client, bad); err == nil {
		t.Fatal("LAN lease omitted from native barrier")
	}
}
func TestWatchdogLANLeaseOnlyPublishedAfterDebouncedTargets(t *testing.T) {
	spec := testWatchdogSpec()
	spec.LANLeaseCIDR = "192.168.88.0/24"
	bundle, err := WatchdogBundle(spec)
	if err != nil {
		t.Fatal(err)
	}
	script := bundle[0].Fields["test-script"]
	add := strings.Index(script, `/ip/firewall/address-list/add list="mc-phase2-up-lease"`)
	if add < 0 || add < strings.Index(script, `($count >= 3)`) || add < strings.LastIndex(script, "/enable $row") {
		t.Fatal("lease precedes debounce or steering activation")
	}
	if !strings.Contains(script, `/ip/firewall/address-list/set $leases timeout=5s`) || !strings.Contains(script, `/ip/firewall/address-list/set $counters address=`) {
		t.Fatal("UP authority must refresh in place without a removal gap")
	}
	if !strings.Contains(script, `address="192.168.88.0/24" timeout=5s`) || !strings.Contains(script, `get $leases dynamic] != true`) || !strings.Contains(script, `[:len $leases] > 1`) {
		t.Fatal("lease admission or finite duration missing")
	}
	for _, down := range []string{bundle[0].Fields["down-script"], bundle[1].Fields["on-event"]} {
		if !strings.Contains(down, `list="mc-phase2-up-lease" and comment="mikrocentauri:phase2:lease:up" and dynamic=yes`) || strings.Contains(down, "/add ") {
			t.Fatal("DOWN/boot does not withdraw lease exactly")
		}
	}
	for _, prefix := range []string{"::/64", "192.168.88.1/24", "0.0.0.0/0", "224.0.0.0/8", "127.0.0.0/8"} {
		spec.LANLeaseCIDR = prefix
		if _, err := DesiredWatchdog(spec); err == nil {
			t.Fatal("invalid lease prefix", prefix)
		}
	}
}

func TestProductionMappingPlacementRefusesInsertedAndDynamicAnchors(t *testing.T) {
	for _, kind := range []string{"stable", "inserted", "dynamic", "missing"} {
		t.Run(kind, func(t *testing.T) {
			b, m, _ := profileFixture(t)
			b.profile.JumpPlaceBefore = "*90"
			anchor := Object{Path: "ip/firewall/nat", ID: "*90", Fields: map[string]string{"chain": "dstnat", "action": "accept", "comment": "existing static anchor"}}
			if kind == "inserted" {
				m.objects = append(m.objects, Object{Path: "ip/firewall/nat", ID: "*91", Fields: map[string]string{"chain": "dstnat", "action": "accept", "comment": "inserted rule"}})
			}
			if kind == "dynamic" {
				anchor.Fields["dynamic"] = "true"
			}
			if kind != "missing" {
				m.objects = append(m.objects, anchor)
			}
			err := b.VerifyProfile(context.Background())
			if (err == nil) != (kind == "stable") || m.mutations != 0 {
				t.Fatal("placement admission incorrect", err)
			}
		})
	}
}

type profileCountingTransport struct {
	base         http.RoundTripper
	mu           sync.Mutex
	reads        map[string]int
	active, peak int
}

func (p *profileCountingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.reads[r.URL.Path]++
	p.active++
	if p.active > p.peak {
		p.peak = p.active
	}
	p.mu.Unlock()
	// Hold independent reads together long enough to exercise the worker bound.
	time.Sleep(10 * time.Millisecond)
	response, err := p.base.RoundTrip(r)
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return response, err
}
func TestProductionProfileFreshSnapshotsDeduplicateAndBoundConcurrentReads(t *testing.T) {
	b, _, _ := profileFixture(t)
	transport := &profileCountingTransport{base: b.client.http.Transport, reads: map[string]int{}}
	b.client.http.Transport = transport
	for attempt := 0; attempt < 2; attempt++ {
		if err := b.VerifyProfile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(transport.reads) != 5 || transport.peak < 2 || transport.peak > 4 {
		t.Fatal("profile proof did not deduplicate/bound reads", transport.reads, transport.peak)
	}
	for path, count := range transport.reads {
		if count != 2 {
			t.Fatal("snapshot reused across invocations or duplicate read", path, count)
		}
	}
}
