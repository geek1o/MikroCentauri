package routeros

import (
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"testing"
)

func TestServicePolicyPlan(t *testing.T) {
	m := coreconfig.Model{SchemaVersion: 2, Instance: "services", Mode: "hybrid", DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/cache.db"}}
	// A DIRECT section is excluded; a disabled proxy section must not steer.
	m.Sections = []coreconfig.Section{{ID: "direct", Name: "Direct", Enabled: true, Outbound: "direct", Domains: []string{"direct.example"}}}
	o := ServicePolicyOptions{LAN: "192.168.88.0/24", Interface: "bridge-lan", Gateway: "172.18.0.2", Table: "mc-services-route", List: "mc-services-dest", Lease: "mc-services-up-lease", DNSPort: 5355}
	if _, e := PlanServicePolicy(m, o); e == nil {
		t.Fatal("empty proxy policy admitted")
	}
	// Use a fixture endpoint to make a valid proxy reference.
	m = capabilityServiceModel(t)
	p, e := PlanServicePolicy(m, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.DNSNAT) != 2 || p.DNS[0].Fields["forward-to"] != o.Gateway {
		t.Fatal("missing private proxy DNS path")
	}
	if len(p.DNS) != 1 || p.DNS[0].Fields["name"] != "video.example" || p.DNS[0].Fields["match-subdomain"] != "true" || len(p.Addresses) != 1 || len(p.Targets) != 2 {
		t.Fatalf("unexpected plan: %+v", p)
	}
	for _, r := range p.Targets {
		if r.Fields["disabled"] != "true" {
			t.Fatal("steering enabled during planning")
		}
	}
	if p.Targets[1].Fields["src-address-list"] != o.Lease || p.Targets[1].Fields["in-interface"] != o.Interface || p.Targets[1].Fields["src-address"] != o.LAN {
		t.Fatal("missing source authority")
	}
	for _, mutate := range []func(*ServicePolicyOptions){func(v *ServicePolicyOptions) { v.Gateway = "192.168.88.3" }, func(v *ServicePolicyOptions) { v.Lease = "mc-services-other" }, func(v *ServicePolicyOptions) { v.List = "foreign" }, func(v *ServicePolicyOptions) { v.LAN = "192.168.88.1/24" }} {
		copy := o
		mutate(&copy)
		if _, e := PlanServicePolicy(m, copy); e == nil {
			t.Fatal("unsafe topology admitted")
		}
	}
	m.Sections[0].DestinationCIDRs = []string{"192.168.0.0/16"}
	if _, e := PlanServicePolicy(m, o); e == nil {
		t.Fatal("private destination admitted")
	}
}

func capabilityServiceModel(t *testing.T) coreconfig.Model {
	t.Helper()
	ep, e := endpoints.ParseURI("ss://YWVzLTEyOC1nY206Zml4dHVyZQ@example.com:8388#fixture")
	if e != nil {
		t.Fatal(e)
	}
	ep.Enabled = true
	return coreconfig.Model{SchemaVersion: 2, Instance: "services", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/cache.db"}, Sections: []coreconfig.Section{
		{ID: "video", Name: "Video", Enabled: true, Outbound: ep.ID, Domains: []string{"video.example"}, DestinationCIDRs: []string{"91.108.4.0/22"}},
		{ID: "off", Name: "Off", Enabled: false, Outbound: ep.ID, Domains: []string{"disabled.example"}},
		{ID: "direct", Name: "Direct", Enabled: true, Outbound: "direct", Domains: []string{"direct.example"}},
	}}
}
