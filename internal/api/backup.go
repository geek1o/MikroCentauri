package api

import (
	"errors"
	"reflect"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/rulesets"
)

const SafeBackupSchema = 2

// SafeExport excludes endpoint keys, passwords, canary/remote URLs and local
// paths. A restore reuses matching private credentials; allocator journals and
// the engine-owned cache are neither exported nor replaced.
type SafeExport struct {
	Sections        []coreconfig.Section      `json:"sections,omitempty"`
	Schema          int                       `json:"schema"`
	Format          string                    `json:"format"`
	Model           coreconfig.ModelPreview   `json:"model"`
	Rules           []coreconfig.Rule         `json:"rules"`
	Services        []coreconfig.Service      `json:"services"`
	DNS             coreconfig.DNS            `json:"dns"`
	SourceDirect    []string                  `json:"source_direct"`
	SourceProxy     []coreconfig.SourcePolicy `json:"source_proxy"`
	DefaultOutbound string                    `json:"default_outbound"`
	RuleSets        []RuleSetReference        `json:"rule_sets,omitempty"`
	Subscriptions   []SubscriptionMetadata    `json:"subscriptions,omitempty"`
	Preferences     *Preferences              `json:"preferences,omitempty"`
}

func Export(m coreconfig.Model) SafeExport {
	dns := m.DNS
	dns.CachePath = ""
	return SafeExport{Sections: m.Sections, Schema: SafeBackupSchema, Format: "mikrocentauri-safe", Model: m.Preview(), Rules: m.Rules, Services: m.Services, DNS: dns, SourceDirect: m.SourceDirect, SourceProxy: m.SourceProxy, DefaultOutbound: m.DefaultOutbound, RuleSets: policyPreview(m).RuleSets}
}

// migrateBackup accepts the historical schema, discarding its local cache path.
// Encrypted/full backups are a separate future format and cannot enter this API.
func migrateBackup(s SafeExport) (SafeExport, error) {
	if s.Format != "mikrocentauri-safe" || (s.Schema != 1 && s.Schema != SafeBackupSchema) {
		return s, errors.New("unsupported backup format")
	}
	if s.Schema == 1 {
		if s.Preferences != nil || len(s.Subscriptions) != 0 || len(s.RuleSets) != 0 {
			return s, errors.New("schema one contains newer fields")
		}
		s.DNS.CachePath = ""
		s.Schema = SafeBackupSchema
	} else if s.DNS.CachePath != "" {
		return s, errors.New("backup contains local cache path")
	}
	if s.Preferences != nil && s.Preferences.Validate() != nil {
		return s, errors.New("invalid backup preferences")
	}
	return s, nil
}
func Restore(s SafeExport, current coreconfig.Model) (coreconfig.Model, error) {
	var e error
	originalSchema := s.Schema
	s, e = migrateBackup(s)
	if e != nil {
		return coreconfig.Model{}, e
	}
	m, e := current.Clone()
	if e != nil {
		return m, e
	}
	p := m.Preview()
	if s.Model.Instance != p.Instance || !reflect.DeepEqual(s.Model.Endpoints, p.Endpoints) || !reflect.DeepEqual(s.Model.WireGuard, p.WireGuard) {
		return m, errors.New("matching local credentials required")
	}
	urls := map[string]string{}
	for _, g := range m.Groups {
		urls[g.ID] = g.URL
	}
	m.Mode = s.Model.Mode
	m.Groups = s.Model.Groups
	for i := range m.Groups {
		if m.Groups[i].URL != "" {
			return m, errors.New("safe backup contains URL")
		}
		m.Groups[i].URL = urls[m.Groups[i].ID]
	}
	if originalSchema != 1 {
		specs := map[string]rulesets.Spec{}
		for _, spec := range m.RuleSets {
			specs[spec.ID] = spec
		}
		m.RuleSets = nil
		seen := map[string]bool{}
		for _, ref := range s.RuleSets {
			spec, ok := specs[ref.ID]
			if !ok || seen[ref.ID] || ref.Format != spec.Format {
				return m, errors.New("matching local ruleset source required")
			}
			seen[ref.ID] = true
			m.RuleSets = append(m.RuleSets, spec)
		}
	}
	m.Sections = s.Sections
	m.Rules = s.Rules
	m.Services = s.Services
	cachePath := m.DNS.CachePath
	m.DNS = s.DNS
	m.DNS.CachePath = cachePath
	m.SourceDirect = s.SourceDirect
	m.SourceProxy = s.SourceProxy
	m.DefaultOutbound = s.DefaultOutbound
	return m, m.Validate()
}
