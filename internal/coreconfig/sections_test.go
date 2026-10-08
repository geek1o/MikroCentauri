package coreconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/singbox"
)

func TestSectionsCompileAlternativeTargetsAndPreserveDeviceScope(t *testing.T) {
	m := fixture(t)
	m.Sections = []Section{{ID: "video", Name: "Video", Enabled: true, Outbound: "manual", Domains: []string{"selected.example"}, DestinationCIDRs: []string{"203.0.113.0/24"}, SourceCIDRs: []string{"192.168.2.10/32"}}, {ID: "exception", Name: "Exception", Enabled: true, Outbound: "direct", Domains: []string{"selected.example"}}}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	rules := m.OrderedRules()
	if rules[0].ID != "section-video-domains" || rules[1].ID != "section-video-networks" || rules[2].ID != "section-exception-domains" {
		t.Fatal("section order not respected", rules)
	}
	if len(rules[0].DestinationCIDRs) != 0 || len(rules[1].Suffixes) != 0 || !reflect.DeepEqual(rules[0].SourceCIDRs, rules[1].SourceCIDRs) {
		t.Fatal("OR branches or device scope lost")
	}
	if m.SelectedOutbound("selected.example") != "direct" {
		t.Fatal("source-qualified rule incorrectly became unconditional")
	}
	m.Sections[0].SourceCIDRs = nil
	if m.SelectedOutbound("selected.example") != "manual" {
		t.Fatal("first section did not win")
	}
	m.Sections[0], m.Sections[1] = m.Sections[1], m.Sections[0]
	if m.SelectedOutbound("selected.example") != "direct" {
		t.Fatal("reordering did not change route")
	}
	m.Sections[0].Enabled = false
	if m.SelectedOutbound("selected.example") != "manual" {
		t.Fatal("disabled section still routes")
	}
	b, e := Generate(m)
	if e != nil {
		t.Fatal(e)
	}
	var generated map[string]any
	if json.Unmarshal(b, &generated) != nil {
		t.Fatal("generation failed")
	}
	if binary := os.Getenv("SING_BOX_BINARY"); binary != "" {
		p := filepath.Join(t.TempDir(), "sections.json")
		if e = os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		if e = singbox.Check(context.Background(), binary, p); e != nil {
			t.Fatal(e)
		}
	}
	cloned, e := m.Clone()
	if e != nil || !reflect.DeepEqual(m.Sections, cloned.Sections) {
		t.Fatal("section clone lost ownership", e)
	}
}
func TestSectionsRejectAmbiguousEmptyAndInvalidPolicies(t *testing.T) {
	cases := map[string]Section{
		"empty":                 {ID: "empty", Name: "Empty", Enabled: true, Outbound: "manual"},
		"unscoped-full":         {ID: "full", Name: "Full", Enabled: true, Outbound: "manual", AllTraffic: true},
		"mixed-full":            {ID: "mixed", Name: "Mixed", Enabled: true, Outbound: "manual", AllTraffic: true, SourceCIDRs: []string{"192.168.1.0/24"}, Domains: []string{"selected.example"}},
		"unknown-outbound":      {ID: "unknown", Name: "Unknown", Domains: []string{"selected.example"}, Outbound: "missing"},
		"fakeip-destination":    {ID: "fake", Name: "Fake", Outbound: "manual", DestinationCIDRs: []string{"198.18.0.0/16"}},
		"invalid-cached-prefix": {ID: "prefix", Name: "Prefix", Outbound: "manual", Lists: []SectionList{{ID: "cached", SHA256: strings.Repeat("a", 64), Prefixes: []string{"bad-prefix"}}}},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture(t)
			m.Sections = []Section{s}
			if m.Validate() == nil {
				t.Fatal("invalid section accepted")
			}
		})
	}
	m := fixture(t)
	m.Sections = []Section{{ID: "device", Name: "Device", Enabled: true, Outbound: "manual", AllTraffic: true, SourceCIDRs: []string{"192.168.2.10/32"}}}
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	m.Rules = append(m.Rules, Rule{ID: "section-device-all", Domains: []string{"collision.example"}, Outbound: "direct"})
	if m.Validate() == nil {
		t.Fatal("generated rule ID collision accepted")
	}
}
