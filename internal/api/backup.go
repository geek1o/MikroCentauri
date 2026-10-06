package api

import (
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"reflect"
)

// SafeExport excludes endpoint keys, passwords, canary URLs and remote URLs.
// Existing private credentials are needed for a validated restore preview.
type SafeExport struct {
	Schema          int                       `json:"schema"`
	Format          string                    `json:"format"`
	Model           coreconfig.ModelPreview   `json:"model"`
	Rules           []coreconfig.Rule         `json:"rules"`
	Services        []coreconfig.Service      `json:"services"`
	DNS             coreconfig.DNS            `json:"dns"`
	SourceDirect    []string                  `json:"source_direct"`
	SourceProxy     []coreconfig.SourcePolicy `json:"source_proxy"`
	DefaultOutbound string                    `json:"default_outbound"`
}

func Export(m coreconfig.Model) SafeExport {
	return SafeExport{1, "mikrocentauri-safe", m.Preview(), m.Rules, m.Services, m.DNS, m.SourceDirect, m.SourceProxy, m.DefaultOutbound}
}
func Restore(s SafeExport, current coreconfig.Model) (coreconfig.Model, error) {
	m, e := current.Clone()
	if e != nil {
		return m, e
	}
	p := m.Preview()
	if s.Schema != 1 || s.Format != "mikrocentauri-safe" || s.Model.Instance != p.Instance || !reflect.DeepEqual(s.Model.Endpoints, p.Endpoints) || !reflect.DeepEqual(s.Model.WireGuard, p.WireGuard) {
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
	m.Rules = s.Rules
	m.Services = s.Services
	m.DNS = s.DNS
	m.SourceDirect = s.SourceDirect
	m.SourceProxy = s.SourceProxy
	m.DefaultOutbound = s.DefaultOutbound
	return m, m.Validate()
}
