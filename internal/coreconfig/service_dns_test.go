package coreconfig

import (
	"context"
	"encoding/json"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/singbox"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceDNSUsesProxyHTTPSBeforeFakeIP(t *testing.T) {
	m := fixture(t)
	o := Options{DNSPort: 5354, MixedPort: 2080, ServiceDNSListen: "172.18.0.2:5355", ServiceDNSOutbound: "manual"}
	raw, e := GenerateWithOptions(m, o)
	if e != nil {
		t.Fatal(e)
	}
	raw, e = GenerateForNamespace(m, namespace.Snapshot{Revision: 1, Known: m.DNS.SelectedDomains, Active: m.DNS.SelectedDomains}, o)
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = json.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	dns := cfg["dns"].(map[string]any)
	if dns["independent_cache"] != true {
		t.Fatal("real and synthetic DNS caches must remain separate")
	}
	rules := dns["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["server"] != "service-dns" {
		t.Fatal("real-answer listener entered FakeIP rules")
	}
	found := false
	for _, v := range dns["servers"].([]any) {
		r := v.(map[string]any)
		if r["tag"] == "service-dns" {
			found = true
			if r["type"] != "https" || r["detour"] != "manual" || r["server"] != "1.1.1.1" || r["tls"].(map[string]any)["server_name"] != "cloudflare-dns.com" {
				t.Fatal("proxy DNS trust/detour lost")
			}
		}
	}
	if !found {
		t.Fatal("missing encrypted resolver")
	}
	if binary := os.Getenv("SING_BOX_BINARY"); binary != "" {
		path := filepath.Join(t.TempDir(), "config.json")
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		if e = singbox.Check(context.Background(), binary, path); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []Options{
		{DNSPort: 5354, MixedPort: 2080, ServiceDNSListen: "0.0.0.0:5355", ServiceDNSOutbound: "manual"},
		{DNSPort: 5354, MixedPort: 2080, ServiceDNSListen: "172.18.0.2:5354", ServiceDNSOutbound: "manual"},
		{DNSPort: 5354, MixedPort: 2080, ServiceDNSListen: "172.18.0.2:5355", ServiceDNSOutbound: "direct"},
		{DNSPort: 5354, MixedPort: 2080, ServiceDNSListen: "172.18.0.2:5355", ServiceDNSOutbound: "missing"},
		{DNSPort: 5354, MixedPort: 2080, ServiceDNSOutbound: "manual"},
	} {
		if _, e = GenerateWithOptions(m, bad); e == nil {
			t.Fatalf("unsafe DNS admitted: %+v", bad)
		}
	}
}
