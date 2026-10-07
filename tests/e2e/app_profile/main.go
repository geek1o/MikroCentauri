// app_profile regenerates signed-by-structure watchdog scripts from a lab profile.
package main

import (
	"encoding/json"
	"flag"
	"mikrocentauri.local/core/internal/application"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
	"os"
	"time"
)

func template(ip, ingress string) (coreconfig.Model, application.Profile) {
	ep, err := endpoints.ParseURI("vless://bf000d23-0752-40b4-affe-68f7707a9661@10.77.0.10:8443?security=none&type=tcp#API-lab-only")
	if err != nil {
		panic(err)
	}
	ep.Enabled = true
	m := coreconfig.Model{SchemaVersion: 2, Instance: "app6", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{ep.ID}, Selected: ep.ID}}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "10.77.0.20", FakeIPRange: "198.19.192.0/18", SelectedDomains: []string{"selected.test", "second.test", "third.test"}, CachePath: "/data/runtime/cache.db"}, Rules: []coreconfig.Rule{{ID: "independent-canary", DestinationCIDRs: []string{"10.77.0.10/32"}, Outbound: "proxy"}, {ID: "selected-domains", Domains: []string{"selected.test", "second.test", "third.test"}, Outbound: "proxy"}}}
	targets := []routeros.Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:app6:route:fakeip", "disabled": "true", "dst-address": m.DNS.FakeIPRange, "gateway": ip, "routing-table": "main", "distance": "1", "scope": "30", "target-scope": "10"}}}
	for _, protocol := range []string{"tcp", "udp"} {
		targets = append(targets, routeros.Object{Path: "ip/firewall/nat", PlaceBefore: map[string]string{"tcp": "*3", "udp": "*4"}[protocol], Fields: map[string]string{"comment": "mikrocentauri:app6:nat:dns-" + protocol, "disabled": "true", "chain": "dstnat", "in-interface": "bridge-lan", "src-address": "192.168.88.0/24", "dst-address": "192.168.88.1", "protocol": protocol, "dst-port": "53", "action": "dst-nat", "to-addresses": ip, "to-ports": "5353"}})
	}
	spec := routeros.WatchdogSpec{Instance: m.Instance, Host: ip, Port: 9099, Interval: 2 * time.Second, Timeout: time.Second, SuccessThreshold: 2, LANLeaseCIDR: "192.168.88.0/24", Targets: targets}
	p := application.Profile{Schema: 1, Directory: "/data/runtime", DNSListen: ip + ":5353", ReadinessListen: ip + ":9099", ObserverClient: "172.18.0.1", IngressInterface: ingress, Table: 100, RulePriority: 10000, LocalRulePriority: 200, LANCIDR: spec.LANLeaseCIDR, LANInterface: "bridge-lan", MappingChain: "mc-app6-backup", MappingPlaceBefore: "*7", Capacity: 32, RealDNSAddress: "10.77.0.20:53", CanaryURL: "http://10.77.0.10:8080/", CanaryPeerIP: "10.77.0.10", Watchdog: spec}
	return m, p
}

func main() {
	var fixture struct {
		Model   coreconfig.Model    `json:"model"`
		Profile application.Profile `json:"profile"`
		Objects []routeros.Object   `json:"objects"`
	}
	ip := flag.String("ip", "", "discovered isolated App IPv4")
	ingress := flag.String("interface", "", "observed Linux ingress")
	hardening := flag.Bool("hardening", false, "synthetic source policy matrix")
	flag.Parse()
	if *ip != "" {
		fixture.Model, fixture.Profile = template(*ip, *ingress)
	} else if err := json.NewDecoder(os.Stdin).Decode(&fixture); err != nil {
		panic(err)
	}
	if *hardening {
		// Explicit TCG profile: the 5s lease profile was not accepted for this matrix.
		fixture.Profile.Watchdog.Interval = 10 * time.Second
		fixture.Profile.Watchdog.Timeout = 3 * time.Second
		fixture.Model.SourceDirect = []string{"192.168.88.30/32"}
		fixture.Model.Rules = append(append(fixture.Model.Rules[:1:1], coreconfig.Rule{ID: "second-domain-direct", Domains: []string{"second.test"}, Outbound: "direct"}), fixture.Model.Rules[1:]...)
		fixture.Model.SourceProxy = []coreconfig.SourcePolicy{{CIDRs: []string{"192.168.88.20/32"}, Outbound: "proxy"}}
	}
	p, m := fixture.Profile, fixture.Model
	if err := p.Validate(m); err != nil {
		panic(err)
	}
	objects, err := routeros.WatchdogBundle(p.Watchdog)
	if err != nil {
		panic(err)
	}
	jump, err := routeros.DesiredMappingJump(routeros.MappingBackendOptions{Instance: m.Instance, Chain: p.MappingChain, LANCIDR: p.LANCIDR, LANInterface: p.LANInterface, FakeIPRange: m.DNS.FakeIPRange, UpLeaseList: "mc-" + m.Instance + "-up-lease", JumpComment: "mikrocentauri:" + m.Instance + ":nat:backup-jump", JumpPlaceBefore: p.MappingPlaceBefore, Observer: objects[0]})
	if err != nil {
		panic(err)
	}
	fixture.Objects = append(append(p.Watchdog.Targets, objects...), jump)
	if err = json.NewEncoder(os.Stdout).Encode(fixture); err != nil {
		panic(err)
	}
}
