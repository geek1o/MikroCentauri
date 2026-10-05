//go:build linux || darwin

package routeros

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func nativeBarrierFixture(t *testing.T, kind string) (*CoreNativeBarrier, *int) {
	t.Helper()
	target := Object{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab:route:fakeip", "disabled": "true", "dst-address": "198.18.0.0/15", "gateway": "172.30.0.2"}}
	observer, err := DesiredWatchdog(WatchdogSpec{Instance: "lab", Host: "172.30.0.2", Port: 9099, Interval: 2 * time.Second, Timeout: time.Second, SuccessThreshold: 2, Targets: []Object{target}})
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]string{}
	for k, v := range observer.Fields {
		row[k] = v
	}
	row["disabled"] = "false"
	row["status"] = "down"
	entries := []map[string]string{}
	lease := map[string]string{"list": "mc-lab-watch-count", "comment": "mikrocentauri:lab:watchdog-counter", "dynamic": "true", "address": "127.0.0.1", "timeout": "5s"}
	switch kind {
	case "up":
		row["status"] = "up"
	case "tampered":
		row["test-script"] = "unsafe"
	case "static":
		lease["dynamic"] = "false"
		entries = append(entries, lease)
	case "foreign":
		lease["comment"] = "user"
		entries = append(entries, lease)
	case "duplicate":
		entries = append(entries, lease, lease)
	case "live":
		entries = append(entries, lease)
	}
	writes := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes++
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/rest/tool/netwatch":
			json.NewEncoder(w).Encode([]map[string]string{row})
		case "/rest/ip/route":
			json.NewEncoder(w).Encode([]map[string]string{target.Fields})
		case "/rest/ip/firewall/address-list":
			json.NewEncoder(w).Encode(entries)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL+"/rest", "lab", "fixture", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	barrier, err := NewCoreNativeBarrier(client, CoreNativeBarrierOptions{Instance: "lab", Observer: observer, ReservedLists: []CoreReservedList{{List: "mc-lab-watch-count", Comment: "mikrocentauri:lab:watchdog-counter"}}})
	if err != nil {
		t.Fatal(err)
	}
	return barrier, &writes
}
func TestCoreNativeBarrierRequiresDownAndEmptyAuthority(t *testing.T) {
	for _, kind := range []string{"clear", "up", "tampered", "static", "foreign", "duplicate", "live"} {
		t.Run(kind, func(t *testing.T) {
			b, writes := nativeBarrierFixture(t, kind)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			err := b.Quarantine(ctx)
			if (err == nil) != (kind == "clear") {
				t.Fatalf("%s: %v", kind, err)
			}
			if *writes != 0 {
				t.Fatal("native barrier mutated configuration")
			}
			if kind == "clear" && b.Verify(ctx) != nil {
				t.Fatal("revoked state rejected")
			}
		})
	}
}
func TestCoreNativeBarrierRejectsHTTPAndLegacyHooks(t *testing.T) {
	c, _ := NewLabClient("http://127.0.0.1/rest", "lab", "fixture", nil)
	if _, err := NewCoreNativeBarrier(c, CoreNativeBarrierOptions{}); err == nil {
		t.Fatal("HTTP accepted")
	}
	c, _ = NewClient("https://127.0.0.1/rest", "lab", "fixture", nil)
	o := CoreNativeBarrierOptions{Instance: "lab", Observer: Object{Path: "tool/netwatch", Fields: map[string]string{"comment": "mikrocentauri:lab:netwatch:readiness", "disabled": "false", "host": "172.30.0.2", "port": "9099", "type": "http-get", "http-codes": "200"}}, ReservedLists: []CoreReservedList{{List: "mc-lab-up-lease", Comment: "mikrocentauri:lab:lease:up", Address: "192.168.88.0/24"}}}
	if _, err := NewCoreNativeBarrier(c, o); err == nil {
		t.Fatal("legacy executable hooks accepted")
	}
	if _, err := NewLabCoreNativeBarrier(c, o); err != nil {
		t.Fatal(err)
	}
}
