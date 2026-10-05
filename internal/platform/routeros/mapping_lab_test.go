package routeros

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"mikrocentauri.local/core/internal/fakeip"
)

func TestLabMappingVerificationAndImmutableConflict(t *testing.T) {
	jump := Object{Path: "ip/firewall/nat", ID: "*J", Fields: map[string]string{"comment": LabMappingJump, "chain": "dstnat", "action": "jump", "jump-target": LabMappingChain, "in-interface": "bridge-lan", "src-address": "192.168.88.0/24", "dst-address": "198.18.0.0/15", "disabled": "true"}}
	m := &mockRouter{objects: []Object{jump}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path != "/rest/ip/firewall/nat" {
			t.Errorf("mapping verification reads unrelated collection: %s", r.URL.Path)
		}
		m.ServeHTTP(w, r)
	}))
	defer s.Close()
	c, _ := NewLabClient(s.URL+"/rest", "lab", "test-password", nil)
	b, _ := NewLabMappingBackend(c)
	map1 := fakeip.Mapping{Domain: "one.test", Fake: netip.MustParseAddr("198.18.0.2"), Real: netip.MustParseAddr("10.77.0.20")}
	ctx := context.Background()
	if b.Verify(ctx, map1) == nil {
		t.Fatal("missing map verified")
	}
	if err := b.Ensure(ctx, map1); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(ctx, map1); err != nil {
		t.Fatal(err)
	}
	if err := b.Ensure(ctx, map1); err != nil {
		t.Fatal(err)
	}
	if m.mutations != 1 {
		t.Fatal("not idempotent")
	}
	map2 := map1
	map2.Real = netip.MustParseAddr("10.77.0.21")
	if b.Ensure(ctx, map2) == nil {
		t.Fatal("alias rebound")
	}
	m.objects[1].Fields["dst-port"] = "443"
	if b.Verify(ctx, map1) == nil {
		t.Fatal("unsupported selector accepted")
	}
	delete(m.objects[1].Fields, "dst-port")
	m.objects[0].Fields["in-interface"] = "ether1"
	if b.Verify(ctx, map1) == nil {
		t.Fatal("unscoped jump accepted")
	}
}

func TestLabTargetTransitionRecoveryAndConflict(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "lost-reply"}[lost], func(t *testing.T) {
			jump := Object{Path: "ip/firewall/nat", ID: "*J", Fields: map[string]string{"comment": LabMappingJump, "chain": "dstnat", "action": "jump", "jump-target": LabMappingChain, "in-interface": "bridge-lan", "src-address": "192.168.88.0/24", "dst-address": "198.18.0.0/15"}}
			before := fakeip.Mapping{Domain: "one.test", Fake: netip.MustParseAddr("198.18.0.2"), Real: netip.MustParseAddr("10.77.0.20")}
			after := before
			after.Real = netip.MustParseAddr("10.77.0.21")
			fields, _ := mappingFields(before)
			m := &mockRouter{objects: []Object{jump, {Path: "ip/firewall/nat", ID: "*M", Fields: fields}}}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					if r.RequestURI != "/rest/ip/firewall/nat/*M" {
						t.Errorf("wrong update ID: %s", r.RequestURI)
					}
					if lost {
						var patch map[string]string
						if err := json.NewDecoder(r.Body).Decode(&patch); err != nil || len(patch) != 1 || patch["to-addresses"] != after.Real.String() {
							t.Errorf("unexpected patch: %v", patch)
						}
						m.mu.Lock()
						m.objects[1].Fields["to-addresses"] = patch["to-addresses"]
						m.mutations++
						m.mu.Unlock()
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return
					}
				}
				m.ServeHTTP(w, r)
			}))
			defer s.Close()
			c, _ := NewLabClient(s.URL+"/rest", "lab", "test-password", nil)
			b, _ := NewLabMappingBackend(c)
			ctx := context.Background()
			if err := b.Update(ctx, before, after); err != nil {
				t.Fatal(err)
			}
			if err := b.Verify(ctx, after); err != nil {
				t.Fatal(err)
			}
			if err := b.Update(ctx, before, after); err != nil || m.mutations != 1 {
				t.Fatalf("recovery wrote twice: %v %d", err, m.mutations)
			}
			transfer := after
			transfer.Domain = "other.test"
			if b.Update(ctx, before, transfer) == nil {
				t.Fatal("domain transfer accepted")
			}
			m.objects[1].Fields["to-addresses"] = "10.77.0.22"
			if b.Update(ctx, before, after) == nil || m.mutations != 1 {
				t.Fatal("third target overwritten")
			}
			m.objects[1].Fields["to-addresses"] = before.Real.String()
			m.objects[1].ID = ""
			if b.Update(ctx, before, after) == nil || m.mutations != 1 {
				t.Fatal("map without an object ID mutated")
			}
			m.objects = m.objects[:1]
			if b.Update(ctx, before, after) == nil || m.mutations != 1 {
				t.Fatal("missing transition rule recreated")
			}
		})
	}
}

func TestLabMappingWriteFailureAndBroadChainRule(t *testing.T) {
	jump := Object{Path: "ip/firewall/nat", ID: "*J", Fields: map[string]string{"comment": LabMappingJump, "chain": "dstnat", "action": "jump", "jump-target": LabMappingChain, "in-interface": "bridge-lan", "src-address": "192.168.88.0/24", "dst-address": "198.18.0.0/15"}}
	m := &mockRouter{objects: []Object{jump}, failAt: 1}
	s := httptest.NewServer(m)
	defer s.Close()
	c, _ := NewLabClient(s.URL+"/rest", "lab", "test-password", nil)
	b, _ := NewLabMappingBackend(c)
	value := fakeip.Mapping{Domain: "one.test", Fake: netip.MustParseAddr("198.18.0.2"), Real: netip.MustParseAddr("10.77.0.20")}
	if b.Ensure(context.Background(), value) == nil {
		t.Fatal("failed write accepted")
	}
	m.objects = append(m.objects, Object{Path: "ip/firewall/nat", ID: "*U", Fields: map[string]string{"chain": LabMappingChain, "action": "accept"}})
	if b.Ensure(context.Background(), value) == nil {
		t.Fatal("broad unowned rule accepted")
	}
	if m.mutations != 1 {
		t.Fatal("wrote into conflicted chain")
	}
}
