package endpoints

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func compatibilityURIs() []string {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	vmess := map[string]string{"v": "2", "ps": "VMess WS", "add": "example.com", "port": "443", "id": "bf000d23-0752-40b4-affe-68f7707a9661", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example", "path": "/socket", "tls": "tls", "sni": "example.com"}
	raw, _ := json.Marshal(vmess)
	return []string{
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=reality&pbk=" + key + "&fp=chrome&spx=%2F&support-x25519mlkem768=true#Reality",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=tls&type=ws&host=cdn.example&path=%2Fsocket&alpn=http%2F1.1#WS",
		"trojan://private-password@example.com:443?security=tls&type=grpc&serviceName=proxy&alpn=h2#GRPC",
		"hysteria2://private-password@example.com:443?sni=example.com&fp=chrome&alpn=h3&obfs=salamander&obfs-password=private-obfs#HY2",
		"ss://YWVzLTEyOC1nY206cHJpdmF0ZS1wYXNzd29yZA@example.com:8388?type=tcp#SS",
		"tuic://bf000d23-0752-40b4-affe-68f7707a9661:private-password@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#TUIC",
		"vmess://" + base64.StdEncoding.EncodeToString(raw),
	}
}
func TestCompatibleShareLinksAndSerialization(t *testing.T) {
	for _, uri := range compatibilityURIs() {
		e, err := ParseURI(uri)
		if err != nil || e.Validate() != nil {
			t.Fatalf("protocol profile rejected: %v / %v", err, e.Validate())
		}
		raw, _ := json.Marshal(e.Preview())
		if strings.Contains(string(raw), "private-password") || strings.Contains(string(raw), "private-obfs") {
			t.Fatal("secret preview")
		}
		e.TransportHost = "bad\r\nHeader: value"
		if e.Validate() == nil {
			t.Fatal("tampered transport accepted")
		}
	}
	for _, uri := range []string{"trojan://private-password@example.com:443?allowInsecure=1", "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=tls&type=xhttp", "trojan://private-password@example.com:443?type=grpc&authority=unsupported.example", "hysteria2://private-password@example.com:443?obfs=unsupported"} {
		if _, err := ParseURI(uri); err == nil || strings.Contains(err.Error(), "private-password") {
			t.Fatal("unsupported/insecure profile accepted or leaked")
		}
	}
}
func TestCompatibilityOutboundsValidateWithPinnedEngine(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("pinned engine required")
	}
	for _, uri := range compatibilityURIs() {
		e, err := ParseURI(uri)
		if err != nil {
			t.Fatal(err)
		}
		cfg := map[string]any{"outbounds": []any{e.Outbound("candidate")}}
		raw, _ := json.Marshal(cfg)
		path := filepath.Join(t.TempDir(), "candidate.json")
		os.WriteFile(path, raw, 0600)
		cmd := exec.Command(binary, "check", "-c", path)
		if err := cmd.Run(); err != nil {
			t.Fatalf("pinned engine rejected %s/%s: %v", e.Protocol, e.Transport, err)
		}
	}
}
