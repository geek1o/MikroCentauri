package routeros

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkReadOnlyProjectionSkipsIPv6AndExcludesPrivateFields(t *testing.T) {
	mutations := 0
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutations++
			w.WriteHeader(403)
			return
		}
		var rows any
		switch r.URL.Path {
		case "/rest/system/resource":
			rows = map[string]string{"total-memory": "1073741824", "free-memory": "500000000", "total-hdd-space": "4294967296", "free-hdd-space": "2000000000", "serial-number": "PRIVATE-SECRET"}
		case "/rest/ip/address":
			rows = []map[string]string{{"address": "192.168.88.1/24", "interface": "bridge-lan", "disabled": "false", "comment": "PRIVATE-SECRET"}, {"address": "fd00::1/64", "interface": "bridge-lan", "disabled": "false"}}
		case "/rest/ip/dhcp-server/lease":
			rows = []map[string]string{{"address": "192.168.88.20", "mac-address": "AA:BB:CC:DD:EE:FF", "host-name": "laptop", "status": "bound", "client-id": "PRIVATE-SECRET"}}
		case "/rest/ip/dns":
			rows = map[string]string{"servers": "1.1.1.1", "dynamic-servers": "1.1.1.1,8.8.8.8", "allow-remote-requests": "true", "use-doh-server": "https://private.example/PRIVATE-SECRET"}
		case "/rest/ip/route":
			rows = []map[string]string{{"dst-address": "0.0.0.0/0", "gateway": "192.0.2.1", "routing-table": "main", "disabled": "false"}, {"dst-address": "0.0.0.0/0", "gateway": "PRIVATE-SECRET", "routing-table": "main", "disabled": "true"}}
		case "/rest/ip/firewall/filter":
			rows = []map[string]string{{"action": "fasttrack-connection", "disabled": "false", "comment": "PRIVATE-SECRET"}, {"action": "fasttrack-connection", "disabled": "true"}, {"action": "accept", "disabled": "false"}}
		default:
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(rows)
	}))
	defer remote.Close()
	c, e := NewClient(remote.URL+"/rest", "fixture", "private-password", remote.Client())
	if e != nil {
		t.Fatal(e)
	}
	v, e := c.Network(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "PRIVATE-SECRET") || mutations != 0 || len(v.Addresses) != 1 || len(v.Devices) != 1 || v.Devices[0].MAC != "aa:bb:cc:dd:ee:ff" || len(v.DNSServers) != 2 || v.FastTrackEnabled != 1 || v.FastTrackRules != 2 || v.MemoryTotal != 1073741824 || v.DefaultRoutes[1].Gateway != "" {
		t.Fatal(string(raw), mutations)
	}
	if _, e = c.request(context.Background(), "PATCH", "ip/address", "*1", map[string]string{"disabled": "true"}); e == nil || mutations != 0 {
		t.Fatal("network reads widened mutation allowlist")
	}
}
func TestNetworkUnavailableAndMalformedResponses(t *testing.T) {
	for _, status := range []int{404, 403, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				if status == 200 {
					w.Write([]byte(`{"total-memory":"10","total-memory":"20"}`))
				}
			}))
			defer remote.Close()
			c, _ := NewClient(remote.URL+"/rest", "fixture", "private-password", remote.Client())
			v, e := c.Network(context.Background())
			if status == 404 {
				if e != nil || v.Available["ip/address"] {
					t.Fatal("unavailable resource fabricated")
				}
			} else if e == nil {
				t.Fatal("denied/malformed discovery accepted")
			}
		})
	}
}

func TestNetworkIPv6ConfigurationIsReadOnlyAndRedacted(t *testing.T) {
	for _, disabled := range []string{"false", "true"} {
		t.Run(disabled, func(t *testing.T) {
			mutations := 0
			remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					mutations++
					w.WriteHeader(403)
					return
				}
				switch r.URL.Path {
				case "/rest/ipv6/settings":
					json.NewEncoder(w).Encode(map[string]string{"disable-ipv6": disabled, "forward": "true", "comment": "PRIVATE-SECRET"})
				case "/rest/ipv6/address":
					w.Write([]byte(`[{"address":"fe80::1/64","disabled":"false"},{"address":"2001:db8::1/64","disabled":"false","comment":"PRIVATE-SECRET"},{"address":"fd00::1/64","disabled":"true"},{"address":"fd00::2/64","disabled":"false","invalid":"true"}]`))
				case "/rest/ipv6/route":
					w.Write([]byte(`[{"dst-address":"::/0","disabled":"false","gateway":"PRIVATE-SECRET"},{"dst-address":"::/0","disabled":"true"},{"dst-address":"2001:db8::/64","active":"true"}]`))
				default:
					w.WriteHeader(404)
				}
			}))
			defer remote.Close()
			c, _ := NewClient(remote.URL+"/rest", "fixture", "private-password", remote.Client())
			v, e := c.Network(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			expected := "configured_enabled"
			if disabled == "true" {
				expected = "configured_disabled"
			}
			if v.IPv6.State != expected || v.IPv6.Forwarding == nil || !*v.IPv6.Forwarding || v.IPv6.EnabledAddresses != 2 || v.IPv6.DefaultRoutes != 2 {
				t.Fatalf("unexpected observation: %+v", v.IPv6)
			}
			raw, _ := json.Marshal(v)
			if strings.Contains(string(raw), "PRIVATE-SECRET") || strings.Contains(string(raw), "2001:db8") {
				t.Fatal("raw IPv6 fields escaped projection")
			}
			for _, path := range []string{"ipv6/settings", "ipv6/address", "ipv6/route"} {
				if !v.Available[path] {
					t.Fatal("missing resource observation")
				}
				for _, method := range []string{"POST", "PATCH", "DELETE"} {
					if _, e := c.request(context.Background(), method, path, "*1", map[string]string{"disabled": "true"}); e == nil {
						t.Fatal("IPv6 discovery widened mutation authority")
					}
				}
			}
			if mutations != 0 {
				t.Fatal("discovery performed a mutation")
			}
		})
	}
}

func TestNetworkIPv6MissingIsUnknownAndMalformedIsDenied(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		status     int
		valid      bool
	}{
		{"ipv6/settings", "", 404, true},
		{"ipv6/settings", `{"disable-ipv6":"false","forward":"false"}`, 200, true},
		{"ipv6/settings", `[]`, 200, false},
		{"ipv6/settings", `[{"disable-ipv6":"false","forward":"true"},{"disable-ipv6":"true","forward":"false"}]`, 200, false},
		{"ipv6/settings", `{"forward":"true"}`, 200, false},
		{"ipv6/settings", `{"disable-ipv6":"maybe","forward":"true"}`, 200, false},
		{"ipv6/settings", `{"disable-ipv6":"false","forward":"maybe"}`, 200, false},
		{"ipv6/settings", `{"disable-ipv6":"false","disable-ipv6":"true","forward":"true"}`, 200, false},
		{"ipv6/settings", "", 403, false},
		{"ipv6/address", `[{"address":"192.0.2.1/24"}]`, 200, false},
		{"ipv6/address", `[{"address":"::ffff:192.0.2.1/128"}]`, 200, false},
		{"ipv6/address", `[{"address":"fd00::1/64","disabled":"false","invalid":"maybe"}]`, 200, false},
		{"ipv6/route", `[{"dst-address":"0.0.0.0/0"}]`, 200, false},
		{"ipv6/route", `[{"dst-address":"::/0","disabled":"maybe"}]`, 200, false},
	} {
		t.Run(tc.path+tc.body+http.StatusText(tc.status), func(t *testing.T) {
			remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rest/"+tc.path {
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer remote.Close()
			c, _ := NewClient(remote.URL+"/rest", "fixture", "private-password", remote.Client())
			v, e := c.Network(context.Background())
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, e)
			}
			if tc.status == 404 && (v.IPv6.State != "unknown" || v.IPv6.Forwarding != nil) {
				t.Fatal("missing settings fabricated a disabled state")
			}
			if tc.valid && tc.status == 200 && (v.IPv6.Forwarding == nil || *v.IPv6.Forwarding) {
				t.Fatal("false forwarding flag lost")
			}
		})
	}
}

func TestNetworkNativeOmittedDisabledFlagsAreUnknown(t *testing.T) {
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/ip/route":
			w.Write([]byte(`[{"dst-address":"0.0.0.0/0","gateway":"192.0.2.1","routing-table":"main","dynamic":"true","active":"true"}]`))
		case "/rest/ip/firewall/filter":
			w.Write([]byte(`[{"action":"fasttrack-connection"}]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer remote.Close()
	c, _ := NewClient(remote.URL+"/rest", "fixture", "private-password", remote.Client())
	v, e := c.Network(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if len(v.DefaultRoutes) != 1 || v.DefaultRoutes[0].DisabledKnown || v.FastTrackEnabled != 0 || v.FastTrackUnknown != 1 || v.FastTrackRules != 1 {
		t.Fatal("missing native flags fabricated a state")
	}
}
