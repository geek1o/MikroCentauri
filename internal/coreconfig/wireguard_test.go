package coreconfig

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/wireguard"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wireguardFixture(t *testing.T) Model {
	t.Helper()
	key := make([]byte, 32)
	peer := make([]byte, 32)
	for i := range key {
		key[i] = 1
		peer[i] = 2
	}
	other, e := ecdh.X25519().NewPrivateKey(peer)
	if e != nil {
		t.Fatal(e)
	}
	ep, e := (wireguard.Endpoint{Name: "Modern WireGuard", Enabled: true, Address: []string{"10.64.0.1/32"}, PrivateKey: base64.StdEncoding.EncodeToString(key), Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: 59999, PublicKey: base64.StdEncoding.EncodeToString(other.PublicKey().Bytes()), AllowedIPs: []string{"0.0.0.0/0"}}}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	return Model{SchemaVersion: 2, Instance: "wireguard", Mode: "socksify", WireGuard: []wireguard.Endpoint{ep}, Groups: []Group{{ID: "manual", Type: "selector", Members: []string{ep.ID}}}, DefaultOutbound: "manual", DNS: DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/wireguard/cache.db"}}
}
func TestModernWireGuardModelGenerationAndClone(t *testing.T) {
	m := wireguardFixture(t)
	b, e := Generate(m)
	if e != nil {
		t.Fatal(e)
	}
	var cfg object
	json.Unmarshal(b, &cfg)
	if len(cfg["endpoints"].([]any)) != 1 {
		t.Fatal("modern WireGuard endpoint missing")
	}
	for _, o := range cfg["outbounds"].([]any) {
		if o.(map[string]any)["type"] == "wireguard" {
			t.Fatal("legacy WireGuard outbound emitted")
		}
	}
	clone, e := m.Clone()
	if e != nil {
		t.Fatal(e)
	}
	clone.WireGuard[0].Address[0] = "10.64.0.2/32"
	clone.WireGuard[0].Peers[0].AllowedIPs[0] = "10.64.0.0/24"
	clone.Groups[0].Members[0] = "direct"
	if m.WireGuard[0].Address[0] != "10.64.0.1/32" || m.WireGuard[0].Peers[0].AllowedIPs[0] != "0.0.0.0/0" || m.Groups[0].Members[0] == "direct" {
		t.Fatal("clone shares nested slices")
	}
	preview, _ := json.Marshal(m.Preview())
	for _, key := range []string{m.WireGuard[0].PrivateKey, m.WireGuard[0].Peers[0].PublicKey, "private_key", "pre_shared_key"} {
		if strings.Contains(string(preview), key) {
			t.Fatal("WireGuard preview leaked key material")
		}
	}
	if binary := os.Getenv("SING_BOX_BINARY"); binary != "" {
		p := filepath.Join(t.TempDir(), "modern.json")
		os.WriteFile(p, b, 0600)
		if e = singbox.Check(context.Background(), binary, p); e != nil {
			t.Fatal(e)
		}
	}
	m.WireGuard[0].Enabled = false
	if m.Validate() == nil {
		t.Fatal("disabled WireGuard reference accepted")
	}
}
