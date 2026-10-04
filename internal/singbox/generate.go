package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/proxy"
)

const Version = "1.14.2"

type obj = map[string]any

// Generate emits only the deliberately narrow Phase-1 configuration. It is not a full rules engine.
func Generate(c config.Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ep, _ := proxy.ParseVLESS(c.VLESSURI)
	outbound := obj{"type": "vless", "tag": "proxy", "server": ep.Server, "server_port": ep.Port, "uuid": ep.UUID, "domain_resolver": "bootstrap"}
	if ep.Flow != "" {
		outbound["flow"] = ep.Flow
	}
	if ep.TLS {
		tls := obj{"enabled": true}
		if ep.SNI != "" {
			tls["server_name"] = ep.SNI
		}
		if ep.Fingerprint != "" {
			tls["utls"] = obj{"enabled": true, "fingerprint": ep.Fingerprint}
		}
		if ep.RealityKey != "" {
			tls["reality"] = obj{"enabled": true, "public_key": ep.RealityKey, "short_id": ep.RealityShortID}
		}
		outbound["tls"] = tls
	}
	rules := []obj{{"inbound": []string{"dns-in"}, "action": "hijack-dns"}, {"action": "sniff"}}
	if len(c.DirectSources) > 0 {
		rules = append(rules, obj{"source_ip_cidr": c.DirectSources, "action": "route", "outbound": "direct"})
	}
	if len(c.ProxySources) > 0 {
		rules = append(rules, obj{"source_ip_cidr": c.ProxySources, "action": "route", "outbound": "proxy"})
	}
	rules = append(rules, obj{"domain": c.Domains, "action": "route", "outbound": "proxy"})
	inbounds := []obj{{"type": "direct", "tag": "dns-in", "listen": "0.0.0.0", "listen_port": 5353}, {"type": "mixed", "tag": "explicit-in", "listen": "0.0.0.0", "listen_port": 2080}}
	if c.Mode != "socksify" {
		inbounds = append(inbounds, obj{"type": "tun", "tag": "gateway-in", "interface_name": "mc-tun", "address": []string{"172.31.255.1/30"}, "mtu": 1500, "auto_route": false, "stack": "gvisor"})
	}
	dnsRules := []obj{{"domain": c.Domains, "query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"}, {"domain": c.Domains, "query_type": []string{"A"}, "action": "route", "server": "fakeip", "rewrite_ttl": 30}}
	// Socksify cannot transport a synthetic destination with domain metadata; use real DNS there.
	servers := []obj{{"type": "udp", "tag": "bootstrap", "server": c.DNSUpstream}}
	if c.Mode != "socksify" {
		servers = append(servers, obj{"type": "fakeip", "tag": "fakeip", "inet4_range": c.FakeIPRange})
	} else {
		dnsRules = []obj{}
	}
	result := obj{"log": obj{"level": "warn"}, "dns": obj{"servers": servers, "rules": dnsRules, "final": "bootstrap"}, "inbounds": inbounds, "outbounds": []obj{{"type": "direct", "tag": "direct", "domain_resolver": "bootstrap"}, outbound}, "route": obj{"rules": rules, "final": "direct", "default_domain_resolver": "bootstrap"}, "experimental": obj{"cache_file": obj{"enabled": true, "path": "/data/singbox-cache.db", "store_fakeip": true}}}
	return json.MarshalIndent(result, "", "  ")
}

// Check never executes a shell and deliberately hides stderr that can contain credentials.
func Check(ctx context.Context, binary, path string) error {
	v, e := exec.CommandContext(ctx, binary, "version").Output()
	if e != nil || !strings.Contains(string(v), "sing-box version "+Version+"\n") {
		return errors.New("sing-box version does not match pinned " + Version)
	}
	if err := exec.CommandContext(ctx, binary, "check", "-c", path).Run(); err != nil {
		return errors.New("sing-box rejected candidate (details suppressed to protect credentials)")
	}
	return nil
}
