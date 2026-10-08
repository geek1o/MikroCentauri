package coreconfig

import (
	"encoding/json"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/wireguard"
)

// Clone returns an independent, fully validated model including secret fields.
// It is controller state, not suitable for diagnostics output.
func (m Model) Clone() (Model, error) {
	b, e := json.Marshal(m)
	if e != nil {
		return Model{}, e
	}
	return Decode(b)
}

type ModelPreview struct {
	Instance  string              `json:"instance"`
	Mode      string              `json:"mode"`
	Endpoints []endpoints.Preview `json:"endpoints"`
	WireGuard []wireguard.Preview `json:"wireguard"`
	Groups    []Group             `json:"groups"`
	RuleCount int                 `json:"rule_count"`
}

// Preview is an explicit projection; WireGuard private/preshared/public key
// material and proxy UUID/password fields never enter the diagnostics object.
func (m Model) Preview() ModelPreview {
	p := ModelPreview{Instance: m.Instance, Mode: m.Mode, RuleCount: len(m.OrderedRules()), Endpoints: []endpoints.Preview{}, WireGuard: []wireguard.Preview{}, Groups: []Group{}}
	for _, e := range m.Endpoints {
		p.Endpoints = append(p.Endpoints, e.Preview())
	}
	for _, e := range m.WireGuard {
		p.WireGuard = append(p.WireGuard, e.Preview())
	}
	for _, g := range m.Groups {
		g.Members = append([]string(nil), g.Members...)
		if g.TestTarget == "" && g.Type == "urltest" {
			for _, target := range []string{"google", "cloudflare", "apple", "mozilla"} {
				if g.TestURL() == TestTargetURL(target) {
					g.TestTarget = target
					break
				}
			}
		}
		g.URL = ""
		p.Groups = append(p.Groups, g)
	}
	return p
}
