package grouphealth

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/wireguard"
	"testing"
	"time"
)

func wgModel(t *testing.T) coreconfig.Model {
	t.Helper()
	key := make([]byte, 32)
	peer := make([]byte, 32)
	for i := range key {
		key[i] = 1
		peer[i] = 2
	}
	pk, e := ecdh.X25519().NewPrivateKey(peer)
	if e != nil {
		t.Fatal(e)
	}
	ep, e := (wireguard.Endpoint{Name: "fixture", Enabled: true, Address: []string{"10.77.0.1/32"}, PrivateKey: base64.StdEncoding.EncodeToString(key), Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: 59999, PublicKey: base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), AllowedIPs: []string{"0.0.0.0/0"}}}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	return coreconfig.Model{SchemaVersion: 2, Instance: "wg-health", Mode: "socksify", WireGuard: []wireguard.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "fallback", Type: "fallback", Members: []string{ep.ID}}}, DefaultOutbound: "fallback", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/wg/cache.db"}}
}
func TestWireGuardFallbackRequiresProbeAndPreservesHistory(t *testing.T) {
	m := wgModel(t)
	o := Options{Model: m, GroupID: "fallback", ApplyModel: func(context.Context, coreconfig.Model) error { return nil }, Quarantine: func(context.Context) error { return nil }}
	if _, e := New(o); e == nil {
		t.Fatal("missing WireGuard probe silently accepted")
	}
	failed := false
	o.ProbeWireGuard = func(ctx context.Context, ep wireguard.Endpoint) (Observation, error) {
		if ep.ID != m.WireGuard[0].ID {
			t.Fatal("wrong WireGuard dispatch")
		}
		if failed {
			return Observation{}, errors.New("failed")
		}
		now := time.Now().UTC()
		return Observation{EndpointID: ep.ID, CheckedAt: now, Health: coreconfig.Health{Available: true, LastSuccess: now, Latency: time.Millisecond}}, nil
	}
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	if e = c.Tick(context.Background()); e != nil || c.Status().Quarantined || c.Status().Selected != m.WireGuard[0].ID {
		t.Fatal(e)
	}
	success := c.Observations()[m.WireGuard[0].ID].LastSuccess
	failed = true
	if e = c.Tick(context.Background()); e == nil || !c.Status().Quarantined {
		t.Fatal("failed WG not quarantined")
	}
	observation := c.Observations()[m.WireGuard[0].ID]
	if observation.Available || observation.LastSuccess != success || observation.LastFailure.IsZero() {
		t.Fatal("WG history lost")
	}
	failed = false
	if e = c.Tick(context.Background()); e != nil || c.Status().Quarantined {
		t.Fatal("WG recovery failed", e)
	}
}
func TestUpdateRejectsWireGuardWithoutCallback(t *testing.T) {
	m := fixture(t)
	c, e := New(Options{Model: m, GroupID: "fallback", Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) { return healthy(ep), nil }, ApplyModel: func(context.Context, coreconfig.Model) error { return nil }, Quarantine: func(context.Context) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	if e = c.UpdateModel(context.Background(), wgModel(t)); e == nil {
		t.Fatal("replacement introduced unobservable WG group")
	}
}

func TestDedicatedWireGuardIdentityGuards(t *testing.T) {
	active := wgModel(t).WireGuard[0]
	dedicated := active
	key := make([]byte, 32)
	for i := range key {
		key[i] = 3
	}
	dedicated.PrivateKey = base64.StdEncoding.EncodeToString(key)
	dedicated.Address = []string{"10.77.0.3/32"}
	dedicated.ID = ""
	dedicated, _ = dedicated.Normalize()
	if !dedicatedWGPeer(active, dedicated) {
		t.Fatal("distinct provisioned peer refused")
	}
	for _, mutate := range []func(*wireguard.Endpoint){
		func(ep *wireguard.Endpoint) { ep.PrivateKey = active.PrivateKey },
		func(ep *wireguard.Endpoint) {
			key, _ := base64.StdEncoding.DecodeString(active.PrivateKey)
			key[0] ^= 1
			ep.PrivateKey = base64.StdEncoding.EncodeToString(key)
		},
		func(ep *wireguard.Endpoint) { ep.Address = []string{"10.77.0.1/24"} },
		func(ep *wireguard.Endpoint) {
			ep.Peers = append([]wireguard.Peer(nil), ep.Peers...)
			ep.Peers[0].Port++
		},
	} {
		candidate := dedicated
		mutate(&candidate)
		candidate.ID = ""
		candidate, _ = candidate.Normalize()
		if dedicatedWGPeer(active, candidate) {
			t.Fatal("unsafe or unrelated probe identity accepted")
		}
	}
}
