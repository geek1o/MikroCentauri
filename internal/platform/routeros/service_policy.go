package routeros

import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"mikrocentauri.local/core/internal/coreconfig"
)

// ServicePolicy is an operator-reviewed real-address companion to the finite
// FakeIP namespace. RouterOS learns CDN addresses from the answers given to LAN
// clients; Telegram's literal-address traffic uses explicit reviewed prefixes.
// Shared destination IPs share routing. Clients using external encrypted DNS do
// not participate in domain learning. This plan never installs or enables rules.
type ServicePolicy struct {
	DNS       []Object `json:"dns"`
	Addresses []Object `json:"addresses"`
	Targets   []Object `json:"targets"`
	DNSNAT    []Object `json:"dns_nat"`
}

type ServicePolicyOptions struct {
	LAN, Interface, Gateway, Table, List, Lease string
	DNSPort                                     uint16
}

func PlanServicePolicy(m coreconfig.Model, o ServicePolicyOptions) (ServicePolicy, error) {
	var plan ServicePolicy
	if err := m.Validate(); err != nil {
		return plan, err
	}
	lan, e := netip.ParsePrefix(o.LAN)
	gw, gerr := netip.ParseAddr(o.Gateway)
	if e != nil || lan != lan.Masked() || !lan.Addr().IsPrivate() || !lan.Addr().Is4() || gerr != nil || !gw.Is4() || !gw.IsPrivate() || lan.Contains(gw) || !mappingIdentifier.MatchString(o.Interface) {
		return plan, errors.New("invalid service policy topology")
	}
	for _, s := range []string{o.Table, o.List, o.Lease} {
		if !mappingIdentifier.MatchString(s) || !strings.HasPrefix(s, "mc-"+m.Instance+"-") {
			return plan, errors.New("invalid service policy ownership")
		}
	}
	if o.Lease != "mc-"+m.Instance+"-up-lease" {
		return plan, errors.New("service steering requires finite readiness lease")
	}
	if o.DNSPort < 1024 {
		return plan, errors.New("explicit private service DNS port required")
	}
	domains, prefixes := map[string]bool{}, map[string]bool{}
	for _, s := range m.Sections {
		if !s.Enabled || s.Outbound == "direct" {
			continue
		}
		if s.AllTraffic || len(s.SourceCIDRs) > 0 {
			return plan, errors.New("service companion requires unscoped destination sections")
		}
		for _, d := range s.Domains {
			domains[d] = true
		}
		for _, p := range s.DestinationCIDRs {
			prefixes[p] = true
		}
		for _, l := range s.Lists {
			for _, d := range l.Domains {
				domains[d] = true
			}
			for _, p := range l.Prefixes {
				prefixes[p] = true
			}
		}
	}
	if len(domains)+len(prefixes) == 0 || len(domains) > 256 || len(prefixes) > 256 {
		return plan, errors.New("service companion target bounds exceeded")
	}
	names := []string{}
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		plan.DNS = append(plan.DNS, Object{Path: "ip/dns/static", Fields: map[string]string{"comment": "mikrocentauri:" + m.Instance + ":dns:" + d, "name": d, "type": "FWD", "forward-to": o.Gateway, "match-subdomain": "true", "address-list": o.List, "disabled": "false"}})
	}
	names = nil
	for p := range prefixes {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		prefix, err := netip.ParsePrefix(p)
		if err != nil || prefix != prefix.Masked() || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.Bits() < 8 {
			return ServicePolicy{}, errors.New("service companion requires reviewed public IPv4 networks")
		}
		plan.Addresses = append(plan.Addresses, Object{Path: "ip/firewall/address-list", Fields: map[string]string{"comment": "mikrocentauri:" + m.Instance + ":network:" + p, "list": o.List, "address": p, "disabled": "false"}})
	}
	// The pinned 7.23.8 FWD target accepts a server address, not host:port.
	// Translate only router-origin DNS to this private App, for both transports.
	for _, protocol := range []string{"tcp", "udp"} {
		plan.DNSNAT = append(plan.DNSNAT, Object{Path: "ip/firewall/nat", Fields: map[string]string{"comment": "mikrocentauri:" + m.Instance + ":nat:service-dns-" + protocol, "chain": "output", "action": "dst-nat", "dst-address": o.Gateway, "protocol": protocol, "dst-port": "53", "to-addresses": o.Gateway, "to-ports": strconv.Itoa(int(o.DNSPort)), "disabled": "false"}})
	}
	plan.Targets = []Object{
		{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:" + m.Instance + ":route:services", "disabled": "true", "dst-address": "0.0.0.0/0", "gateway": o.Gateway, "routing-table": o.Table, "distance": "1", "scope": "30", "target-scope": "10"}},
		{Path: "ip/firewall/mangle", Fields: map[string]string{"comment": "mikrocentauri:" + m.Instance + ":mangle:services", "disabled": "true", "chain": "prerouting", "in-interface": o.Interface, "src-address": o.LAN, "src-address-list": o.Lease, "dst-address-list": o.List, "action": "mark-routing", "new-routing-mark": o.Table, "passthrough": "false"}},
	}
	return plan, nil
}
