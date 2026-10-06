package api

import "mikrocentauri.local/core/internal/coreconfig"

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
	p := PolicyPreview{Rules: m.Rules, Services: m.Services, SourceDirect: m.SourceDirect, SourceProxy: m.SourceProxy, DefaultOutbound: m.DefaultOutbound, DNS: DNSPolicy{m.DNS.Bootstrap, m.DNS.FakeIPRange, m.DNS.SelectedDomains, m.DNS.SelectedSuffixes}, RuleSets: []RuleSetReference{}}
	for _, s := range m.RuleSets {
		p.RuleSets = append(p.RuleSets, RuleSetReference{s.ID, s.Format})
	}
	return p
}
