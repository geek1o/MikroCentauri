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
	Gateway  string `json:"gateway"`
	Table    string `json:"table"`
	Disabled bool   `json:"disabled"`
}
type NetworkDevice struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	Status   string `json:"status"`
}

var networkPaths = map[string]bool{"ip/address": true, "ip/dhcp-server/lease": true, "ip/dns": true}

func networkText(s string) bool { return len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n") }
func (c *Client) Network(ctx context.Context) (Network, error) {
	result := Network{Available: map[string]bool{}, Addresses: []NetworkAddress{}, DefaultRoutes: []NetworkRoute{}, Devices: []NetworkDevice{}, DNSServers: []string{}}
	for _, path := range []string{"system/resource", "ip/address", "ip/dhcp-server/lease", "ip/dns", "ip/route", "ip/firewall/filter"} {
		b, available, e := c.capabilityGET(ctx, path)
		if e != nil {
			return Network{}, e
		}
		result.Available[path] = available
		if !available {
			continue
		}
		rows, e := scalarRows(b, path == "system/resource" || path == "ip/dns")
		if e != nil {
			return Network{}, e
		}
		for _, row := range rows {
			switch path {
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
				disabled, e := capabilityBool(row, "disabled")
				if e != nil {
					return Network{}, e
				}
				result.DefaultRoutes = append(result.DefaultRoutes, NetworkRoute{gateway, row["routing-table"], disabled})
			case "ip/firewall/filter":
				if row["action"] != "fasttrack-connection" {
					continue
				}
				result.FastTrackRules++
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
