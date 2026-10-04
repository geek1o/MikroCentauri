package proxy

import (
	"strings"
	"testing"
)

const testUUID = "bf000d23-0752-40b4-affe-68f7707a9661"

func TestParseVLESS(t *testing.T) {
	e, err := ParseVLESS("vless://" + testUUID + "@[::1]:443?security=tls&sni=example.com&type=tcp#Test%20node")
	if err != nil || e.Server != "::1" || !e.TLS || e.Name != "Test node" {
		t.Fatalf("parse failed %v", err)
	}
	for _, uri := range []string{
		"vless://SECRET@example.com:443",
		"vless://" + testUUID + "@example.com:0",
		"vless://" + testUUID + "@example.com:443?type=ws",
		"vless://" + testUUID + "@example.com:443?security=none&security=tls",
		"vless://" + testUUID + "@example.com:443?security=reality",
		"vless://" + testUUID + "@example.com:443?unknown=SECRET",
		"vless://" + testUUID + "@example.com:443?flow=xtls-rprx-vision",
	} {
		_, e := ParseVLESS(uri)
		if e == nil {
			t.Fatal("accepted unsupported URI")
		}
		if strings.Contains(e.Error(), "SECRET") || strings.Contains(e.Error(), testUUID) {
			t.Fatal("credential leaked in error")
		}
	}
}
