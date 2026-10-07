package coreconfig

import (
	"errors"
	"mikrocentauri.local/core/internal/rulesets"
	"net/netip"
	"sort"
	"strings"
)

func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Lower priorities run first. Equal priorities retain declared order.
func (m Model) OrderedRules() []Rule {
	r := []Rule{}
	for _, v := range m.Rules {
		if v.IsEnabled() {
			r = append(r, v)
		}
	}
	sort.SliceStable(r, func(i, j int) bool { return r[i].Priority < r[j].Priority })
	return r
}
func portsValid(p []uint16) bool {
	seen := map[uint16]bool{}
	if len(p) > 4096 {
		return false
	}
	for _, v := range p {
		if v == 0 || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func networksValid(n []string) bool {
	seen := map[string]bool{}
	for _, v := range n {
		if (v != "tcp" && v != "udp") || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
func (m Model) validateRuleExtensions(pool netip.Prefix) error {
	if len(m.Services) > 256 || len(m.RuleSets) > 256 {
		return errors.New("service or rule-set bound exceeded")
	}
	services := map[string]bool{}
	for _, s := range m.Services {
		if !idPattern.MatchString(s.ID) || services[s.ID] || len(s.Name) > 256 || strings.ContainsAny(s.Name, "\x00\r\n") || len(s.Ports) == 0 || len(s.Networks) == 0 || !portsValid(s.Ports) || !networksValid(s.Networks) {
			return errors.New("invalid service list")
		}
		services[s.ID] = true
	}
	sets := map[string]bool{}
	for _, s := range m.RuleSets {
		if s.Validate() != nil || sets[s.ID] {
			return errors.New("invalid rule-set reference")
		}
		sets[s.ID] = true
	}
	for _, r := range m.Rules {
		if len(r.Name) > 256 || strings.ContainsAny(r.Name, "\x00\r\n") || r.Priority < -1000000 || r.Priority > 1000000 || cidrs(r.SourceCIDRs, pool) != nil || len(r.Services) > 256 || len(r.RuleSets) > 256 {
			return errors.New("invalid rule metadata or sources")
		}
		seen := map[string]bool{}
		for _, id := range r.Services {
			if !services[id] || seen[id] {
				return errors.New("unknown or duplicate rule service")
			}
			seen[id] = true
		}
		seen = map[string]bool{}
		for _, id := range r.RuleSets {
			if !sets[id] || seen[id] {
				return errors.New("unknown or duplicate rule-set")
			}
			seen[id] = true
		}
		if len(r.Services) > 0 && (len(r.Ports) > 0 || r.Network != "") {
			return errors.New("service lists cannot be combined with inline ports/network")
		}
	}
	return nil
}
func normalizedPorts(p []uint16) []uint16 {
	n := append([]uint16(nil), p...)
	sort.Slice(n, func(i, j int) bool { return n[i] < n[j] })
	return n
}
func (m Model) generatedRule(r Rule) object {
	match := object{}
	if len(r.Domains) > 0 {
		match["domain"] = r.Domains
	}
	if len(r.Suffixes) > 0 {
		match["domain_suffix"] = r.Suffixes
	}
	if len(r.DestinationCIDRs) > 0 {
		match["ip_cidr"] = r.DestinationCIDRs
	}
	if len(r.SourceCIDRs) > 0 {
		match["source_ip_cidr"] = r.SourceCIDRs
	}
	if len(r.Ports) > 0 {
		match["port"] = normalizedPorts(r.Ports)
	}
	if r.Network != "" {
		match["network"] = r.Network
	}
	if len(r.RuleSets) > 0 {
		match["rule_set"] = r.RuleSets
	}
	if len(r.Services) > 0 {
		clauses := []object{}
		for _, id := range r.Services {
			for _, s := range m.Services {
				if s.ID == id {
					nets := append([]string(nil), s.Networks...)
					sort.Strings(nets)
					clauses = append(clauses, object{"port": normalizedPorts(s.Ports), "network": nets})
					break
				}
			}
		}
		service := object{"type": "logical", "mode": "or", "rules": clauses}
		if len(match) > 0 {
			match = object{"type": "logical", "mode": "and", "rules": []object{match, service}}
		} else {
			match = service
		}
	}
	match["action"] = "route"
	match["outbound"] = r.Outbound
	return match
}
func (m Model) namespaceTerminalRules(domain string, retired bool) []object {
	if retired {
		return []object{{"domain": []string{domain}, "action": "route", "outbound": "direct"}}
	}
	result := []object{}
	for _, r := range m.OrderedRules() {
		if len(r.DestinationCIDRs) > 0 || len(r.RuleSets) > 0 {
			continue
		}
		conditional := len(r.SourceCIDRs) > 0 || len(r.Ports) > 0 || r.Network != "" || len(r.Services) > 0
		matches := len(r.Domains) == 0 && len(r.Suffixes) == 0 && conditional
		for _, d := range r.Domains {
			if d == domain {
				matches = true
			}
		}
		for _, s := range r.Suffixes {
			if domain == s || strings.HasSuffix(domain, "."+s) {
				matches = true
			}
		}
		if matches {
			if !conditional {
				break
			}
			if len(r.Ports) == 0 && r.Network == "" && len(r.Services) == 0 {
				result = append(result, object{"domain": []string{domain}, "source_ip_cidr": r.SourceCIDRs, "action": "route", "outbound": r.Outbound})
			} else {
				predicate := m.generatedRule(r)
				delete(predicate, "action")
				delete(predicate, "outbound")
				result = append(result, object{"type": "logical", "mode": "and", "rules": []object{{"domain": []string{domain}}, predicate}, "action": "route", "outbound": r.Outbound})
			}
		}
	}
	return append(result, object{"domain": []string{domain}, "action": "route", "outbound": m.SelectedOutbound(domain)})
}
func (m Model) attachRuleSets(cfg object, artifacts []rulesets.Artifact) error {
	if len(artifacts) != len(m.RuleSets) {
		return errors.New("resolved rule-set artifacts required")
	}
	available := map[string]rulesets.Artifact{}
	for _, a := range artifacts {
		if a.Validate() != nil {
			return errors.New("invalid resolved rule-set artifact")
		}
		if _, ok := available[a.ID]; ok {
			return errors.New("duplicate resolved rule-set artifact")
		}
		available[a.ID] = a
	}
	entries := []object{}
	for _, s := range m.RuleSets {
		a, ok := available[s.ID]
		if !ok {
			return errors.New("missing resolved rule-set artifact")
		}
		entries = append(entries, object{"type": "local", "tag": s.ID, "format": "binary", "path": a.Path})
	}
	if len(entries) > 0 {
		cfg["route"].(map[string]any)["rule_set"] = entries
	}
	return nil
}
