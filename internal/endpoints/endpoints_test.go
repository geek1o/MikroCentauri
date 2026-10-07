package endpoints

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProtocolsAndRename(t *testing.T) {
	for _, uri := range []string{"vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=tls", "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388", "trojan://secret@example.com:443?sni=example.com", "hysteria2://secret@example.com:443"} {
		e, err := ParseURI(uri + "#first")
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseURI(uri + "#renamed")
		if err != nil || e.ID != r.ID {
			t.Fatal("rename changed ID")
		}
		b, _ := json.Marshal(e.Preview())
		if strings.Contains(string(b), "secret") {
			t.Fatal("preview leaks")
		}
		if e.Outbound("node")["server"] != "example.com" {
			t.Fatal("outbound")
		}
	}
}
func TestRejectAndRedact(t *testing.T) {
	for _, u := range []string{"trojan://secret@example.com:443?allowInsecure=1", "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388?plugin=secret", "hysteria2://secret@example.com:0", "trojan://secret:pass@example.com:443", "ss://bm9uZTpzZWNyZXQ@example.com:443"} {
		_, err := ParseURI(u)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("accepted or leaked")
		}
	}
}
func TestSerializedValidation(t *testing.T) {
	e, err := ParseURI("trojan://secret@example.com:443#friendly")
	if err != nil || e.Validate() != nil {
		t.Fatal("valid endpoint")
	}
	e.Protocol = "ss"
	if e.Validate() == nil {
		t.Fatal("tampered endpoint")
	}
	for _, uri := range []string{"vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=reality&pbk=secret&fp=chrome", "trojan://secret@example.com:443#bad%0Aname"} {
		if _, err := ParseURI(uri); err == nil {
			t.Fatal("invalid key/name")
		}
	}
}
