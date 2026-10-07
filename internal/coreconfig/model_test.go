package coreconfig

import (
	"context"
	"encoding/json"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) Model {
	t.Helper()
	uris := []string{"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:443?security=tls&sni=example.com#vless", "ss://aes-256-gcm:public-test-secret@127.0.0.1:8388#ss", "trojan://public-test-secret@127.0.0.1:443?sni=example.com#trojan", "hysteria2://public-test-secret@127.0.0.1:443?sni=example.com#hy2"}
	m := Model{SchemaVersion: 2, Instance: "core", Mode: "hybrid", DefaultOutbound: "manual", DNS: DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", SelectedDomains: []string{"selected.example"}, CachePath: "/data/core/cache.db"}, SourceDirect: []string{"192.168.1.1/32"}, SourceProxy: []SourcePolicy{{CIDRs: []string{"192.168.1.0/24"}, Outbound: "manual"}}}
	for _, u := range uris {
		ep, e := endpoints.ParseURI(u)
		if e != nil {
			t.Fatal(e)
		}
		m.Endpoints = append(m.Endpoints, ep)
	}
	ids := []string{}
	for _, e := range m.Endpoints {
		ids = append(ids, e.ID)
	}
	m.Groups = []Group{{ID: "auto", Type: "urltest", Members: ids, URL: "https://example.com/generate_204", Interval: "3m", Tolerance: 50}, {ID: "backup", Type: "fallback", Members: ids}, {ID: "manual", Type: "selector", Members: []string{"auto", "backup", ids[0]}, Selected: "auto"}}
	m.Rules = []Rule{{ID: "selected", Domains: []string{"selected.example"}, Outbound: "backup"}, {ID: "service", Suffixes: []string{"example.com"}, Ports: []uint16{443}, Network: "tcp", Outbound: "manual"}, {ID: "address", DestinationCIDRs: []string{"203.0.113.0/24"}, Outbound: ids[0]}}
	return m
}
func TestPinnedGeneration(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for pinned validation")
	}
	for _, mode := range []string{"hybrid", "full", "socksify"} {
		t.Run(mode, func(t *testing.T) {
			m := fixture(t)
			m.Mode = mode
			b, e := Generate(m)
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "candidate.json")
			if e = os.WriteFile(path, b, 0600); e != nil {
				t.Fatal(e)
			}
			if e = singbox.Check(context.Background(), binary, path); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(b), `"type": "fallback"`) {
				t.Fatal("invented sing-box fallback")
			}
		})
	}
}
func TestImmutableFakeIPOrderingAndPrivateDNS(t *testing.T) {
	b, e := Generate(fixture(t))
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(b, &cfg); e != nil {
		t.Fatal(e)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[1].(map[string]any)["outbound"] != "direct" || rules[2].(map[string]any)["outbound"] != "manual" || rules[3].(map[string]any)["outbound"] != "backup" || rules[4].(map[string]any)["action"] != "sniff" {
		t.Fatal("source precedence or pre-sniff FakeIP identity lost")
	}
	for _, raw := range cfg["inbounds"].([]any) {
		in := raw.(map[string]any)
		if in["type"] != "tun" && in["listen"] != "127.0.0.1" {
			t.Fatal("public engine listener")
		}
	}
}
func TestValidationRejectsAmbiguity(t *testing.T) {
	cases := map[string]func(*Model){"cycle": func(m *Model) { m.Groups[0].Members = []string{"manual"} }, "unknown": func(m *Model) { m.Rules[0].Outbound = "missing" }, "disabled": func(m *Model) { m.Endpoints[0].Enabled = false }, "selected": func(m *Model) { m.Groups[2].Selected = "direct" }, "prefix": func(m *Model) { m.SourceDirect = []string{"198.18.0.0/16"} }, "unaligned": func(m *Model) { m.SourceDirect = []string{"192.168.1.1/24"} }, "zero-port": func(m *Model) { m.Rules[0].Ports = []uint16{0} }, "empty-rule": func(m *Model) { m.Rules[0].Domains = nil }, "invalid-domain": func(m *Model) { m.Rules[0].Domains = []string{"UPPER.example"} }, "dns-suffix": func(m *Model) { m.DNS.SelectedSuffixes = []string{"example.com"} }, "cache": func(m *Model) { m.DNS.CachePath = "/tmp/cache.db" }, "credential-url": func(m *Model) { m.Groups[0].URL = "https://secret@example.com/" }, "interval": func(m *Model) { m.Groups[0].Interval = "0s" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture(t)
			mutate(&m)
			if m.Validate() == nil {
				t.Fatal("invalid model accepted")
			}
		})
	}
}
func TestStrictDecode(t *testing.T) {
	m := fixture(t)
	b, _ := json.Marshal(m)
	if _, e := Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{`{"schema_version":2,"schema_version":2}`, string(b) + ` {}`, `{"unknown":true}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		if _, e := Decode([]byte(bad)); e == nil {
			t.Fatal("bad JSON accepted")
		}
	}
}

func TestModeAndEnabledEndpointRequirements(t *testing.T) {
	m := fixture(t)
	m.DefaultOutbound = "direct"
	if e := m.Validate(); e != nil {
		t.Fatalf("hybrid may use direct default with explicit selected routes: %v", e)
	}
	m.Mode = "full"
	if m.Validate() == nil {
		t.Fatal("full mode silently accepted DIRECT default")
	}
	m.Mode = "socksify"
	m.Groups = nil
	m.Rules = nil
	m.SourceProxy = nil
	m.SourceDirect = nil
	for i := range m.Endpoints {
		m.Endpoints[i].Enabled = false
	}
	if m.Validate() == nil {
		t.Fatal("all-disabled core accepted")
	}
}
func TestFallbackAndSelection(t *testing.T) {
	m := fixture(t)
	g := m.Groups[1]
	now := time.Now()
	h := map[string]Health{g.Members[0]: {Available: true, LastSuccess: now.Add(-time.Hour)}, g.Members[1]: {Available: true, LastSuccess: now.Add(-time.Second)}}
	selected, e := FallbackSelection(g, h, now, time.Minute)
	if e != nil || selected != g.Members[1] {
		t.Fatalf("fallback=%s error=%v", selected, e)
	}
	next, e := m.Select(g.ID, selected)
	if e != nil || next.Groups[1].Selected != selected || m.Groups[1].Selected != "" {
		t.Fatal("selection did not isolate model")
	}
	h[g.Members[1]] = Health{Available: true, LastSuccess: now.Add(-time.Second), LastFailure: now}
	if _, e = FallbackSelection(g, h, now, time.Minute); e == nil {
		t.Fatal("failed probe treated healthy")
	}
	if _, e = m.Select("auto", g.Members[0]); e == nil {
		t.Fatal("manual URLTest accepted")
	}
}
