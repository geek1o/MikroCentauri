package coreconfig

import "testing"

func TestEmptyDirectManagementModelCannotSelectTraffic(t *testing.T) {
	m := Model{SchemaVersion: 2, Instance: "first-install", Mode: "hybrid", DefaultOutbound: "direct", DNS: DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/runtime/cache.db"}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Model){
		func(m *Model) { m.DefaultOutbound = "proxy" },
		func(m *Model) { m.Mode = "full" },
		func(m *Model) { m.DNS.SelectedDomains = []string{"selected.example"} },
		func(m *Model) {
			m.Rules = []Rule{{ID: "selected", Domains: []string{"selected.example"}, Outbound: "direct"}}
		},
		func(m *Model) {
			m.SourceProxy = []SourcePolicy{{CIDRs: []string{"192.168.88.0/24"}, Outbound: "proxy"}}
		},
	} {
		candidate := m
		change(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("empty bootstrap selected traffic")
		}
	}
}
