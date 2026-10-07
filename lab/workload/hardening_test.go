package main

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitFixtureAAAAAndManagedTestTarget(t *testing.T) {
	old := dnsFixture.Load()
	defer dnsFixture.Store(old)
	dnsFixture.Store(&dnsOverride{Target: "10.77.0.20", TTL: 5, IPv6Target: "fd7a:7:2::20"})
	reply, e := dnsReply(query("selected.test", 28), "10.77.0.20")
	if e != nil || binary.BigEndian.Uint16(reply[6:8]) != 1 || binary.BigEndian.Uint16(reply[len(reply)-18:len(reply)-16]) != 16 {
		t.Fatal("explicit IPv6 fixture missing")
	}
	dnsFixture.Store(nil)
	reply, e = dnsReply(query("selected.test", 28), "10.77.0.20")
	if e != nil || binary.BigEndian.Uint16(reply[6:8]) != 0 {
		t.Fatal("fixture opt-in changed default AAAA")
	}
}
func TestHardeningControlsRefuseArbitraryTargets(t *testing.T) {
	mux := http.NewServeMux()
	hardeningHandlers(mux, "client")
	for _, tc := range []struct{ path, body string }{
		{"/dns-query", `{"domain":"private.example","server":"127.0.0.1","type":1}`},
		{"/dns-query", `{"domain":"selected.test","server":"10.77.0.20","type":255}`},
		{"/dns-query", `{"domain":"selected.test","server":"169.254.169.254","type":1}`},
		{"/ipv6-request", `{"source":"::1","path":"/phase7-v6-test"}`},
		{"/ipv6-request", `{"source":"fd7a:7:1::10","path":"/arbitrary"}`},
		{"/ipv6-request", `{"source":"fd7a:7:1::10","path":"/phase7-v6-test","target":"::1"}`},
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body)))
		if response.Code != 400 {
			t.Fatal(tc.path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("POST", "/proxy-control", strings.NewReader(`{"action":"stop"}`)))
	if response.Code != 404 {
		t.Fatal("client may signal proxy process")
	}
	server := http.NewServeMux()
	hardeningHandlers(server, "serve")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest("POST", "/proxy-control", strings.NewReader(`{"action":"kill"}`)))
	if response.Code != 400 {
		t.Fatal("unbounded signal accepted")
	}
}
