package api

import (
	"mikrocentauri.local/core/internal/coreconfig"
	"reflect"
)

type RuleSetReference struct {
	ID     string `json:"id"`
	Format string `json:"format"`
}
type DNSPolicy struct {
	Bootstrap   string   `json:"bootstrap"`
	FakeIPRange string   `json:"fakeip_range"`
	Domains     []string `json:"selected_domains"`
	Suffixes    []string `json:"selected_suffixes"`
}
type PolicyPreview struct {
	Sections        []coreconfig.Section      `json:"sections,omitempty"`
	Rules           []coreconfig.Rule         `json:"rules"`
	Services        []coreconfig.Service      `json:"services"`
	SourceDirect    []string                  `json:"source_direct"`
	SourceProxy     []coreconfig.SourcePolicy `json:"source_proxy"`
	DefaultOutbound string                    `json:"default_outbound"`
	DNS             DNSPolicy                 `json:"dns"`
	RuleSets        []RuleSetReference        `json:"rule_sets"`
}

// policyPreview makes submitted rules/source/DNS/service changes reviewable;
// remote artifact URLs, credentials and local cache/artifact paths stay private.
func policyPreview(m coreconfig.Model) PolicyPreview {
	p := PolicyPreview{Sections: m.Sections, Rules: m.Rules, Services: m.Services, SourceDirect: m.SourceDirect, SourceProxy: m.SourceProxy, DefaultOutbound: m.DefaultOutbound, DNS: DNSPolicy{m.DNS.Bootstrap, m.DNS.FakeIPRange, m.DNS.SelectedDomains, m.DNS.SelectedSuffixes}, RuleSets: []RuleSetReference{}}
	for _, s := range m.RuleSets {
		p.RuleSets = append(p.RuleSets, RuleSetReference{s.ID, s.Format})
	}
	return p
}

// planChanges lists changed policy sections without exposing secret values or
// filesystem/source URLs. The plan also carries the full redacted candidate.
func planChanges(before, after coreconfig.Model, restore *RestoreSettings) []string {
	changes := []string{}
	add := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			changes = append(changes, name)
		}
	}
	add("mode", before.Mode, after.Mode)
	add("endpoints", before.Endpoints, after.Endpoints)
	add("wireguard", before.WireGuard, after.WireGuard)
	add("groups", before.Groups, after.Groups)
	add("rules", before.Rules, after.Rules)
	add("sections", before.Sections, after.Sections)
	add("services", before.Services, after.Services)
	add("source_direct", before.SourceDirect, after.SourceDirect)
	add("source_proxy", before.SourceProxy, after.SourceProxy)
	add("dns", before.DNS, after.DNS)
	add("rule_sets", before.RuleSets, after.RuleSets)
	add("default_outbound", before.DefaultOutbound, after.DefaultOutbound)
	if restore != nil {
		if restore.Preferences != nil {
			changes = append(changes, "preferences")
		}
		if len(restore.Subscriptions) > 0 {
			changes = append(changes, "subscription_metadata")
		}
	}
	return changes
}
