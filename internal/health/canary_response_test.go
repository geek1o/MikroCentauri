package health

import (
	"strings"
	"testing"
)

func TestPublicTracePeerExtractionRejectsAmbiguity(t *testing.T) {
	for _, body := range []string{"fl=abc\nip=203.0.113.9\ncolo=NRT\n", "ip=203.0.113.9\r\n", "ip=::ffff:203.0.113.9\n"} {
		ip, e := ParseCanaryIP([]byte(body), CanaryCloudflareTrace)
		if e != nil || ip.String() != "203.0.113.9" {
			t.Fatal("valid trace rejected", e)
		}
	}
	for _, body := range []string{"ip=203.0.113.9\nip=203.0.113.9\n", "ip=not-an-ip\n", "notip=203.0.113.9\n", "ip=0.0.0.0\n", "ip=127.0.0.1\n", "ip=2001:db8::1%private-zone\n", strings.Repeat("x", 4097)} {
		if _, e := ParseCanaryIP([]byte(body), CanaryCloudflareTrace); e == nil {
			t.Fatal("ambiguous or invalid peer accepted")
		}
	}
	ip, e := ParseCanaryIP([]byte(`{"remote_ip":"10.77.0.10"}`), "")
	if e != nil || ip.String() != "10.77.0.10" {
		t.Fatal("legacy lab response changed", e)
	}
	if loopback, e := ParseCanaryIP([]byte(`{"remote_ip":"127.0.0.1"}`), ""); e != nil || loopback.String() != "127.0.0.1" {
		t.Fatal("legacy isolated canary changed", e)
	}
	if _, e := ParseCanaryIP([]byte("ip=203.0.113.9"), "unknown"); e == nil {
		t.Fatal("unknown format accepted")
	}
}
func TestPublicTraceConfigurationKeepsTLSAndExpectedPeerRequired(t *testing.T) {
	base := HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "https://1.1.1.1/cdn-cgi/trace", ExpectedPeerIP: "203.0.113.9", ResponseFormat: CanaryCloudflareTrace}
	if _, e := NewHTTPProbe(base); e != nil {
		t.Fatal(e)
	}
	missing := base
	missing.ExpectedPeerIP = ""
	if _, e := NewHTTPProbe(missing); e == nil {
		t.Fatal("public response bypassed expected peer requirement")
	}
	cleartext := base
	cleartext.URL = "http://1.1.1.1/cdn-cgi/trace"
	if _, e := NewHTTPProbe(cleartext); e == nil {
		t.Fatal("public canary accepted without TLS")
	}
	unknown := base
	unknown.ResponseFormat = "unknown"
	if _, e := NewHTTPProbe(unknown); e == nil {
		t.Fatal("unknown format accepted")
	}
}
