package routeros

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Network is a GET-only, explicit projection. Raw comments, scripts, DHCP
// options, DNS static records, URLs and credential-bearing fields never escape.
type Network struct {
	FastTrackUnknown  int              `json:"fasttrack_unknown"`
	IPv6              IPv6Observation  `json:"ipv6"`
	Available         map[string]bool  `json:"available"`
	Addresses         []NetworkAddress `json:"addresses"`
	DefaultRoutes     []NetworkRoute   `json:"default_routes"`
	Devices           []NetworkDevice  `json:"devices"`
	DNSServers        []string         `json:"dns_servers"`
	DNSRemoteRequests bool             `json:"dns_remote_requests"`
	FastTrackRules    int              `json:"fasttrack_rules"`
	FastTrackEnabled  int              `json:"fasttrack_enabled"`
	MemoryTotal       uint64           `json:"memory_total"`
	MemoryFree        uint64           `json:"memory_free"`
	DiskTotal         uint64           `json:"disk_total"`
	DiskFree          uint64           `json:"disk_free"`
}
type NetworkAddress struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Disabled  bool   `json:"disabled"`
}
type NetworkRoute struct {
	DisabledKnown bool   `json:"disabled_known"`
	Gateway       string `json:"gateway"`
	Table         string `json:"table"`
	Disabled      bool   `json:"disabled"`
}
type NetworkDevice struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	Status   string `json:"status"`
}

// Configuration observations never establish effective IPv6 isolation.
type IPv6Observation struct {
	State            string `json:"state"`
	Forwarding       *bool  `json:"forwarding"`
	EnabledAddresses int    `json:"enabled_addresses"`
	DefaultRoutes    int    `json:"default_routes"`
}

var networkPaths = map[string]bool{"ip/address": true, "ip/dhcp-server/lease": true, "ip/dns": true, "ipv6/settings": true, "ipv6/address": true, "ipv6/route": true}

func networkText(s string) bool { return len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n") }
func (c *Client) Network(ctx context.Context) (Network, error) {
	result := Network{IPv6: IPv6Observation{State: "unknown"}, Available: map[string]bool{}, Addresses: []NetworkAddress{}, DefaultRoutes: []NetworkRoute{}, Devices: []NetworkDevice{}, DNSServers: []string{}}
	for _, path := range []string{"system/resource", "ip/address", "ip/dhcp-server/lease", "ip/dns", "ip/route", "ip/firewall/filter", "ipv6/settings", "ipv6/address", "ipv6/route"} {
		b, available, e := c.capabilityGET(ctx, path)
		if e != nil {
			return Network{}, e
		}
		result.Available[path] = available
		if !available {
			continue
		}
		rows, e := scalarRows(b, path == "system/resource" || path == "ip/dns" || path == "ipv6/settings")
		if e != nil {
			return Network{}, e
		}
		if path == "ipv6/settings" && len(rows) != 1 {
			return Network{}, errors.New("invalid IPv6 settings cardinality")
		}
		for _, row := range rows {
			switch path {
			case "ipv6/settings":
				// Required flags must not silently become false when missing.
				if row["disable-ipv6"] == "" || row["forward"] == "" {
					return Network{}, errors.New("missing IPv6 settings flags")
				}
				disabled, e := capabilityBool(row, "disable-ipv6")
				if e != nil {
					return Network{}, e
				}
				forwarding, e := capabilityBool(row, "forward")
				if e != nil {
					return Network{}, e
				}
				result.IPv6.State = "configured_enabled"
				if disabled {
					result.IPv6.State = "configured_disabled"
				}
				result.IPv6.Forwarding = &forwarding
			case "ipv6/address":
				prefix, e := netip.ParsePrefix(row["address"])
				if e != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
					return Network{}, errors.New("invalid IPv6 address")
				}
				disabled, e := capabilityBool(row, "disabled")
				if e != nil {
					return Network{}, e
				}
				invalid := false
				if _, present := row["invalid"]; present {
					invalid, e = capabilityBool(row, "invalid")
					if e != nil {
						return Network{}, e
					}
				}
				if !disabled && !invalid {
					result.IPv6.EnabledAddresses++
				}
			case "ipv6/route":
				prefix, e := netip.ParsePrefix(row["dst-address"])
				if e != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
					return Network{}, errors.New("invalid IPv6 route")
				}
				// Dynamic native routes omit disabled. Count observed defaults, not reachability.
				for _, flag := range []string{"disabled", "active"} {
					if _, present := row[flag]; present {
						if _, e := capabilityBool(row, flag); e != nil {
							return Network{}, e
						}
					}
				}
				if prefix.Bits() == 0 {
					result.IPv6.DefaultRoutes++
				}
			case "system/resource":
				for _, v := range []struct {
					key string
					out *uint64
				}{{"total-memory", &result.MemoryTotal}, {"free-memory", &result.MemoryFree}, {"total-hdd-space", &result.DiskTotal}, {"free-hdd-space", &result.DiskFree}} {
					if raw := row[v.key]; raw != "" {
						n, e := strconv.ParseUint(raw, 10, 64)
						if e != nil {
							return Network{}, errors.New("invalid resource size")
						}
						*v.out = n
					}
				}
			case "ip/address":
				p, e := netip.ParsePrefix(row["address"])
				if e != nil || !networkText(row["interface"]) {
					return Network{}, errors.New("invalid network address")
				}
				if !p.Addr().Is4() {
					continue
				}
				disabled, e := capabilityBool(row, "disabled")
				if e != nil {
					return Network{}, e
				}
				result.Addresses = append(result.Addresses, NetworkAddress{p.String(), row["interface"], disabled})
			case "ip/dhcp-server/lease":
				ip, e := netip.ParseAddr(row["address"])
				mac, me := net.ParseMAC(row["mac-address"])
				if e != nil || me != nil || !ip.Is4() || len(mac) != 6 || !networkText(row["host-name"]) {
					return Network{}, errors.New("invalid DHCP device")
				}
				status := row["status"]
				switch status {
				case "bound", "waiting", "testing", "authorizing", "conflict", "declined", "offered":
				default:
					status = "unknown"
				}
				result.Devices = append(result.Devices, NetworkDevice{row["host-name"], ip.String(), mac.String(), status})
			case "ip/dns":
				result.DNSRemoteRequests, e = capabilityBool(row, "allow-remote-requests")
				if e != nil {
					return Network{}, e
				}
				seen := map[string]bool{}
				for _, raw := range strings.Split(row["servers"]+","+row["dynamic-servers"], ",") {
					if raw == "" {
						continue
					}
					ip, e := netip.ParseAddr(raw)
					if e != nil {
						return Network{}, errors.New("invalid DNS server")
					}
					if !seen[ip.String()] {
						result.DNSServers = append(result.DNSServers, ip.String())
						seen[ip.String()] = true
					}
				}
			case "ip/route":
				if row["dst-address"] != "0.0.0.0/0" {
					continue
				}
				gateway := row["gateway"]
				if ip, e := netip.ParseAddr(gateway); e == nil {
					gateway = ip.String()
				} else {
					gateway = ""
				}
				if !networkText(row["routing-table"]) {
					return Network{}, errors.New("invalid route table")
				}
				disabled := false
				_, known := row["disabled"]
				if known {
					disabled, e = capabilityBool(row, "disabled")
					if e != nil {
						return Network{}, e
					}
				}
				result.DefaultRoutes = append(result.DefaultRoutes, NetworkRoute{Gateway: gateway, Table: row["routing-table"], Disabled: disabled, DisabledKnown: known})
			case "ip/firewall/filter":
				if row["action"] != "fasttrack-connection" {
					continue
				}
				result.FastTrackRules++
				if _, known := row["disabled"]; !known {
					result.FastTrackUnknown++
					continue
				}
				disabled, e := capabilityBool(row, "disabled")
				if e != nil {
					return Network{}, e
				}
				if !disabled {
					result.FastTrackEnabled++
				}
			}
		}
	}
	return result, nil
}
