package coreconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"mikrocentauri.local/core/internal/rulesets"
	"path/filepath"
	"strings"
)

type object = map[string]any

// Options are private process listeners. External DNS publication belongs to
// dnsgate and traffic activation belongs to the RouterOS activation controller.
type Options struct {
	ControlPort   uint16
	ControlSecret string
	RuleSets      []rulesets.Artifact
	DNSPort       uint16
	MixedPort     uint16
	// CachePath is a trusted runtime mapping; callers must enforce private
	// directory and file ownership. Application models cannot provide it.
	CachePath string
}

func Generate(m Model) ([]byte, error) {
	return GenerateWithOptions(m, Options{DNSPort: 5353, MixedPort: 2080})
}
func GeneratePinned(m Model) ([]byte, error) { return Generate(m) }
func GenerateWithOptions(m Model, o Options) ([]byte, error) {
	if e := m.Validate(); e != nil {
		return nil, e
	}
	m = m.withSectionRules()
	if o.DNSPort == 0 || o.MixedPort == 0 || o.DNSPort == o.MixedPort {
		return nil, errors.New("invalid private listener ports")
	}
	cachePath := m.DNS.CachePath
	if o.CachePath != "" {
		if len(o.CachePath) > 4096 || strings.ContainsAny(o.CachePath, "\x00\r\n") || !filepath.IsAbs(o.CachePath) || filepath.Clean(o.CachePath) != o.CachePath || filepath.Dir(o.CachePath) == o.CachePath {
			return nil, errors.New("invalid trusted cache mapping")
		}
		cachePath = o.CachePath
	}
	if o.ControlPort != 0 && (o.ControlPort == o.DNSPort || o.ControlPort == o.MixedPort || len(o.ControlSecret) < 32 || len(o.ControlSecret) > 256 || strings.ContainsAny(o.ControlSecret, "\x00\r\n")) {
		return nil, errors.New("invalid private controller")
	}
	if o.ControlPort == 0 && o.ControlSecret != "" {
		return nil, errors.New("controller port required")
	}
	out := []object{{"type": "direct", "tag": "direct", "domain_resolver": "bootstrap"}}
	for _, ep := range m.Endpoints {
		if ep.Enabled {
			ob := ep.Outbound(ep.ID)
			ob["domain_resolver"] = "bootstrap"
			out = append(out, ob)
		}
	}
	for _, g := range m.Groups {
		typ := g.Type
		if typ == "fallback" {
			typ = "selector"
		}
		ob := object{"type": typ, "tag": g.ID, "outbounds": g.Members, "interrupt_exist_connections": false}
		if typ == "selector" {
			selected := g.Selected
			if selected == "" {
				selected = g.Members[0]
			}
			ob["default"] = selected
		} else {
			ob["url"] = g.TestURL()
			if g.Interval != "" {
				ob["interval"] = g.Interval
			}
			if g.Tolerance != 0 {
				ob["tolerance"] = g.Tolerance
			}
		}
		out = append(out, ob)
	}
	route := []object{{"inbound": []string{"dns-in"}, "action": "hijack-dns"}}
	if len(m.SourceDirect) > 0 {
		route = append(route, object{"source_ip_cidr": m.SourceDirect, "action": "route", "outbound": "direct"})
	}
	for _, s := range m.SourceProxy {
		route = append(route, object{"source_ip_cidr": s.CIDRs, "action": "route", "outbound": s.Outbound})
	}
	// The FakeIP matcher receives rewritten domain metadata, so CIDR-based sniff
	// exclusion does not preserve alias identity. Terminal exact domain rules must
	// precede sniff. Classification beyond this known set can use sniff later.
	if m.Mode != "socksify" {
		for _, domain := range m.DNS.SelectedDomains {
			route = append(route, m.namespaceTerminalRules(domain, false)...)
		}
	}
	route = append(route, object{"action": "sniff"})
	for _, r := range m.OrderedRules() {
		route = append(route, m.generatedRule(r))
	}
	servers := []object{{"type": "udp", "tag": "bootstrap", "server": m.DNS.Bootstrap}}
	dnsRules := []object{}
	if m.Mode != "socksify" && len(m.DNS.SelectedDomains) > 0 {
		servers = append(servers, object{"type": "fakeip", "tag": "fakeip", "inet4_range": m.DNS.FakeIPRange})
		dnsRules = append(dnsRules, object{"domain": m.DNS.SelectedDomains, "query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"}, object{"domain": m.DNS.SelectedDomains, "query_type": []string{"A"}, "action": "route", "server": "fakeip", "rewrite_ttl": 30})
	}
	in := []object{{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": o.DNSPort}, {"type": "mixed", "tag": "explicit-in", "listen": "127.0.0.1", "listen_port": o.MixedPort}}
	if m.Mode != "socksify" {
		in = append(in, object{"type": "tun", "tag": "gateway-in", "interface_name": "mc-tun", "address": []string{"172.31.255.1/30"}, "mtu": 1500, "auto_route": false, "stack": "gvisor"})
	}
	result := object{"log": object{"level": "warn"}, "dns": object{"servers": servers, "rules": dnsRules, "final": "bootstrap"}, "inbounds": in, "outbounds": out, "route": object{"rules": route, "final": m.DefaultOutbound, "default_domain_resolver": "bootstrap"}, "experimental": object{"cache_file": object{"enabled": true, "path": cachePath, "store_fakeip": m.Mode != "socksify"}}}
	if o.ControlPort != 0 {
		result["experimental"].(object)["clash_api"] = object{"external_controller": fmt.Sprintf("127.0.0.1:%d", o.ControlPort), "secret": o.ControlSecret, "access_control_allow_origin": []string{"http://127.0.0.1"}}
	}
	modern := []object{}
	for _, ep := range m.WireGuard {
		if ep.Enabled {
			endpoint, e := ep.Build(ep.ID)
			if e != nil {
				return nil, errors.New("invalid WireGuard generation")
			}
			endpoint["domain_resolver"] = "bootstrap"
			modern = append(modern, endpoint)
		}
	}
	if len(modern) > 0 {
		result["endpoints"] = modern
	}
	if err := m.attachRuleSets(result, o.RuleSets); err != nil {
		return nil, err
	}
	return json.MarshalIndent(result, "", "  ")
}

// SelectedOutbound finds a domain-only route for immutable FakeIP binding.
// Qualified source/service policies are compiled as exact known-domain
// predicates before sniff; this returns the unconditional domain fallback.
func (m Model) SelectedOutbound(domain string) string {
	for _, r := range m.OrderedRules() {
		if len(r.Ports) > 0 || r.Network != "" || len(r.DestinationCIDRs) > 0 || len(r.SourceCIDRs) > 0 || len(r.Services) > 0 || len(r.RuleSets) > 0 {
			continue
		}
		for _, d := range r.Domains {
			if d == domain {
				return r.Outbound
			}
		}
		for _, s := range r.Suffixes {
			if domain == s || strings.HasSuffix(domain, "."+s) {
				return r.Outbound
			}
		}
	}
	return m.DefaultOutbound
}
