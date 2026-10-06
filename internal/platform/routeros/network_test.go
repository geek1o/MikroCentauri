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
