package coreconfig

import (
	"encoding/json"
	"mikrocentauri.local/core/internal/namespace"
	"testing"
)

func TestRulePriorityEnabledAndTerminalSources(t *testing.T) {
	m := fixture(t)
	no := false
	m.Rules = []Rule{{ID: "later", Priority: 10, Domains: []string{"selected.example"}, Outbound: "manual"}, {ID: "off", Enabled: &no, Priority: -20, Domains: []string{"selected.example"}, Outbound: "direct"}, {ID: "device", Priority: -10, Domains: []string{"selected.example"}, SourceCIDRs: []string{"192.168.1.0/24"}, Outbound: "direct"}, {ID: "early", Priority: 0, Domains: []string{"selected.example"}, Outbound: "backup"}, {ID: "tie", Priority: 0, Domains: []string{"selected.example"}, Outbound: "manual"}}
	r := m.OrderedRules()
	if len(r) != 4 || r[0].ID != "device" || r[1].ID != "early" || r[2].ID != "tie" || r[3].ID != "later" {
		t.Fatal("priority/enable order changed")
	}
	if m.SelectedOutbound("selected.example") != "backup" {
		t.Fatal("source rule incorrectly became universal")
	}
	s := namespace.Snapshot{Revision: 1, Known: []string{"selected.example"}, Active: []string{"selected.example"}}
	b, e := GenerateForNamespace(m, s, Options{DNSPort: 5353, MixedPort: 2080})
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateForNamespace(b, m, s, Options{DNSPort: 5353, MixedPort: 2080}); e != nil {
		t.Fatal(e)
	}
	var root object
	json.Unmarshal(b, &root)
	rules := root["route"].(map[string]any)["rules"].([]any)
	if rules[3].(map[string]any)["outbound"] != "direct" || rules[4].(map[string]any)["outbound"] != "backup" || rules[5].(map[string]any)["action"] != "sniff" {
		t.Fatal("source pre-sniff terminal ordering lost")
	}
}
func TestServiceTupleGeneration(t *testing.T) {
	m := fixture(t)
	m.Services = []Service{{ID: "web", Ports: []uint16{443, 80}, Networks: []string{"tcp"}}, {ID: "dns", Ports: []uint16{53}, Networks: []string{"udp"}}}
	r := Rule{ID: "services", Services: []string{"web", "dns"}, SourceCIDRs: []string{"192.168.1.0/24"}, Outbound: "direct"}
	m.Rules = append(m.Rules, r)
	if e := m.Validate(); e != nil {
		t.Fatal(e)
	}
	rule := m.generatedRule(r)
	if rule["mode"] != "and" {
		t.Fatal("service source predicate lost")
	}
	or := rule["rules"].([]object)[1]
	clauses := or["rules"].([]object)
	if clauses[0]["port"].([]uint16)[0] != 80 || len(clauses) != 2 || clauses[0]["network"].([]string)[0] != "tcp" || clauses[1]["network"].([]string)[0] != "udp" {
		t.Fatal("service tuples broadened or not normalized")
	}
	m.Rules[len(m.Rules)-1].Services = []string{"unknown"}
	if m.Validate() == nil {
		t.Fatal("unknown service accepted")
	}
}
