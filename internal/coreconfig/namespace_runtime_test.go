package coreconfig

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinnedNamespaceCachedAliasBinding(t *testing.T) {
	bin := os.Getenv("SING_BOX_BINARY")
	if bin == "" {
		t.Skip("set SING_BOX_BINARY for private FakeIP process proof")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "bound-target") }))
	defer target.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "bound-target") }))
	defer secure.Close()
	resolver, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer resolver.Close()
	go dnsFixture(resolver)
	dir := t.TempDir()
	ssPort := freePort(t)
	ssPath := filepath.Join(dir, "server.json")
	writeJSON(t, ssPath, object{"log": object{"level": "warn"}, "inbounds": []object{{"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ssPort, "method": "aes-256-gcm", "password": "public-test-secret"}}, "outbounds": []object{{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct"}, "dns": object{"servers": []object{{"type": "udp", "tag": "bootstrap", "server": "127.0.0.1", "server_port": resolver.LocalAddr().(*net.UDPAddr).Port}}, "final": "bootstrap"}})
	stopServer := runPinned(t, bin, ssPath, ssPort)
	defer stopServer()
	relay, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	var proxyHits atomic.Int64
	go func() {
		for {
			c, e := relay.Accept()
			if e != nil {
				return
			}
			proxyHits.Add(1)
			go func() {
				defer c.Close()
				u, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssPort), time.Second)
				if e != nil {
					return
				}
				defer u.Close()
				done := make(chan struct{})
				go func() { io.Copy(u, c); u.(*net.TCPConn).CloseWrite(); close(done) }()
				io.Copy(c, u)
				c.Close()
				<-done
			}()
		}
	}()
	ep, e := endpoints.ParseURI("ss://aes-256-gcm:public-test-secret@" + relay.Addr().String() + "#alias-fixture")
	if e != nil {
		t.Fatal(e)
	}
	m := Model{SchemaVersion: 2, Instance: "binding", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, Groups: []Group{{ID: "manual", Type: "selector", Members: []string{ep.ID}}}, DefaultOutbound: "manual", DNS: DNS{Bootstrap: "127.0.0.1", FakeIPRange: "198.18.0.0/15", SelectedDomains: []string{"selected.example"}, CachePath: "/data/binding/cache.db"}}
	s := namespace.Snapshot{Revision: 1, Known: []string{"selected.example", "retired.example"}, Active: []string{"selected.example"}}
	o := Options{DNSPort: freePort(t), MixedPort: freePort(t), CachePath: filepath.Join(dir, "cache.db")}
	start := func() func() {
		t.Helper()
		b, e := GenerateForNamespace(m, s, o)
		if e != nil {
			t.Fatal(e)
		}
		if e = ValidateForNamespace(b, m, s, o); e != nil {
			t.Fatal(e)
		}
		var cfg object
		json.Unmarshal(b, &cfg)
		// Host fixture removes TUN and substitutes a controlled ephemeral bootstrap
		// UDP server. The untouched generation passed strict namespace preflight.
		cfg["inbounds"] = cfg["inbounds"].([]any)[:2]
		cfg["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server_port"] = resolver.LocalAddr().(*net.UDPAddr).Port
		p := filepath.Join(dir, "engine.json")
		writeJSON(t, p, cfg)
		if e = singbox.Check(context.Background(), bin, p); e != nil {
			t.Fatal(e)
		}
		return runPinned(t, bin, p, o.MixedPort)
	}
	stop := start()
	defer func() { stop() }()
	selected := queryAlias(t, o.DNSPort, "selected.example")
	retired := queryAlias(t, o.DNSPort, "retired.example")
	requestAlias(t, o.MixedPort, selected, target.URL, "unselected.example", "")
	if proxyHits.Load() != 1 {
		t.Fatal("Host changed active alias proxy identity")
	}
	requestAlias(t, o.MixedPort, selected, secure.URL, "unselected.example", "unselected.example")
	if proxyHits.Load() != 2 {
		t.Fatal("SNI changed active alias proxy identity")
	}
	requestAlias(t, o.MixedPort, retired, target.URL, "selected.example", "")
	if proxyHits.Load() != 2 {
		t.Fatal("retired alias promoted to proxy by Host")
	}
	stop()
	m.DNS.SelectedDomains = nil
	s.Revision = 2
	s.Active = []string{}
	stop = start()
	if got := queryAlias(t, o.DNSPort, "selected.example"); got != selected {
		t.Fatal("retirement changed persisted alias")
	}
	requestAlias(t, o.MixedPort, selected, target.URL, "selected.example", "")
	requestAlias(t, o.MixedPort, selected, secure.URL, "selected.example", "selected.example")
	if proxyHits.Load() != 2 {
		t.Fatal("cached retired alias promoted to proxy by Host or SNI")
	}
}
func dnsFixture(c net.PacketConn) {
	b := make([]byte, 2048)
	for {
		n, addr, e := c.ReadFrom(b)
		if e != nil {
			return
		}
		q := append([]byte(nil), b[:n]...)
		if len(q) < 17 {
			continue
		}
		end := 12
		for end < len(q) && q[end] != 0 {
			end += int(q[end]) + 1
		}
		end++
		if end+4 > len(q) {
			continue
		}
		typ := binary.BigEndian.Uint16(q[end : end+2])
		r := append([]byte(nil), q[:end+4]...)
		binary.BigEndian.PutUint16(r[2:4], 0x8180)
		binary.BigEndian.PutUint16(r[6:8], 0)
		binary.BigEndian.PutUint16(r[8:10], 0)
		binary.BigEndian.PutUint16(r[10:12], 0)
		if typ == 1 {
			binary.BigEndian.PutUint16(r[6:8], 1)
			r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
		}
		c.WriteTo(r, addr)
	}
}
func queryAlias(t *testing.T, port uint16, name string) string {
	t.Helper()
	q := []byte{0x42, 0x01, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	c, e := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(q)
	b := make([]byte, 2048)
	n, e := c.Read(b)
	if e != nil || n < 16 {
		t.Fatal("private DNS alias lookup failed")
	}
	alias := net.IP(b[n-4 : n]).String()
	if !strings.HasPrefix(alias, "198.18.") && !strings.HasPrefix(alias, "198.19.") {
		t.Fatalf("not a synthetic alias: %s", alias)
	}
	return alias
}
func requestAlias(t *testing.T, mixed uint16, alias, target, host, sni string) {
	t.Helper()
	u, _ := url.Parse(target)
	port, _ := strconv.Atoi(u.Port())
	c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", mixed), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	c.Write([]byte{5, 1, 0})
	head := make([]byte, 2)
	if _, e = io.ReadFull(c, head); e != nil || head[1] != 0 {
		t.Fatal("SOCKS greeting failed")
	}
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(alias).To4()...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	reply := make([]byte, 4)
	if _, e = io.ReadFull(c, reply); e != nil || reply[1] != 0 {
		t.Fatal("synthetic SOCKS connect failed")
	}
	length := 4
	if reply[3] == 4 {
		length = 16
	}
	tail := make([]byte, length+2)
	if _, e = io.ReadFull(c, tail); e != nil {
		t.Fatal(e)
	}
	var conn net.Conn = c
	if sni != "" {
		conn = tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		defer conn.Close()
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	b, e := io.ReadAll(io.LimitReader(conn, 4096))
	if e != nil || !strings.Contains(string(b), "bound-target") {
		t.Fatalf("bound request failed: %v", e)
	}
}
