package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func query(name string, typ uint16) []byte {
	b := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(typ>>8), byte(typ), 0, 1)
	return b
}
func TestDNSAnswers(t *testing.T) {
	for _, tc := range []struct {
		name         string
		typ          uint16
		count, rcode uint16
	}{{"selected.test", 1, 1, 0}, {"unselected.test", 1, 1, 0}, {"selected.test", 28, 0, 0}, {"unknown.test", 1, 0, 3}} {
		t.Run(tc.name+string(rune(tc.typ)), func(t *testing.T) {
			q := query(tc.name, tc.typ)
			b, err := dnsReply(q, "10.77.0.20")
			if err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint16(b[:2]) != 0x1234 || binary.BigEndian.Uint16(b[6:8]) != tc.count || binary.BigEndian.Uint16(b[2:4])&15 != tc.rcode {
				t.Fatalf("invalid response: %x", b)
			}
			if tc.count == 1 {
				tail := b[len(q):]
				if binary.BigEndian.Uint32(tail[6:10]) != 5 || !net.IP(tail[12:]).Equal(net.ParseIP("10.77.0.20")) {
					t.Fatalf("invalid answer %x", tail)
				}
			}
		})
	}
}
func TestDNSMalformed(t *testing.T) {
	cases := [][]byte{nil, make([]byte, 12), append([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 12), append([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 63, 1)}
	for _, q := range cases {
		if _, err := dnsReply(q, "10.77.0.20"); err == nil {
			t.Fatalf("accepted malformed %x", q)
		}
	}
}

func TestChurnFixtureDoesNotChangeCanary(t *testing.T) {
	defer dnsFixture.Store(nil)
	dnsFixture.Store(&dnsOverride{Target: "10.77.0.21", TTL: 9})
	for _, name := range []string{"second.test", "selected.test"} {
		q := query(name, 1)
		b, err := dnsReply(q, "10.77.0.20")
		if err != nil {
			t.Fatal(err)
		}
		wantIP, wantTTL := "10.77.0.20", uint32(5)
		if name == "second.test" {
			wantIP, wantTTL = "10.77.0.21", 9
		}
		if !net.IP(b[len(b)-4:]).Equal(net.ParseIP(wantIP)) || binary.BigEndian.Uint32(b[len(b)-10:]) != wantTTL {
			t.Fatalf("incorrect fixture: %x", b)
		}
	}
	dnsFixture.Store(&dnsOverride{Target: "10.77.0.21", TTL: 9, Fail: true})
	b, _ := dnsReply(query("second.test", 1), "10.77.0.20")
	if binary.BigEndian.Uint16(b[6:8]) != 0 || binary.BigEndian.Uint16(b[2:4])&15 != 2 {
		t.Fatalf("expected no-answer SERVFAIL: %x", b)
	}
}

func TestCachedAddressWorkloadSkipsUnavailableDNS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(targetHTTP))
	defer server.Close()
	_, portString, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := net.LookupPort("tcp", portString)
	out := runWorkload(context.Background(), "127.0.0.1:1", workloadRequest{Domain: "second.test", Address: "127.0.0.1", SkipDNS: true, Port: port, Path: "/cached"}, false)
	if out.Error != "" || out.ResolvedIPv4 != "127.0.0.1" {
		t.Fatalf("cached request consulted DNS: %+v", out)
	}
}
func TestDNSTCPFraming(t *testing.T) {
	server, client := net.Pipe()
	go handleDNSTCP(server, "10.77.0.20")
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	// Reuse one TCP session for two framed questions.
	for _, typ := range []uint16{1, 28} {
		q := query("selected.test", typ)
		length := []byte{byte(len(q) >> 8), byte(len(q))}
		go func() { _, _ = client.Write(append(length, q...)) }()
		var prefix [2]byte
		if _, err := io.ReadFull(client, prefix[:]); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(client, answer); err != nil {
			t.Fatal(err)
		}
		want, _ := dnsReply(q, "10.77.0.20")
		if string(answer) != string(want) {
			t.Fatalf("TCP differs from DNS response")
		}
	}
}
func TestWorkloadHTTPAndUDP(t *testing.T) {
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(b)
			if err != nil {
				return
			}
			reply, err := dnsReply(b[:n], "127.0.0.1")
			if err == nil {
				_, _ = dns.WriteTo(reply, peer)
			}
		}
	}()
	server := httptest.NewServer(http.HandlerFunc(targetHTTP))
	defer server.Close()
	_, portString, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := net.LookupPort("tcp", portString)
	req := workloadRequest{Domain: "selected.test", Port: port, Source: "127.0.0.1", Path: "/probe?id=42"}
	out := runWorkload(context.Background(), dns.LocalAddr().String(), req, false)
	if out.Error != "" || out.ResolvedIPv4 != "127.0.0.1" || out.ProxySeenIP != "127.0.0.1" {
		t.Fatalf("HTTP result: %+v", out)
	}
	target := out.Target.(map[string]any)
	if target["path"] != "/probe?id=42" {
		t.Fatalf("path lost: %+v", target)
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 1024)
		n, peer, err := udp.ReadFrom(b)
		if err == nil {
			_, _ = udp.WriteTo(b[:n], peer)
		}
	}()
	req.Port = udp.LocalAddr().(*net.UDPAddr).Port
	req.Payload = "probe-123"
	out = runWorkload(context.Background(), dns.LocalAddr().String(), req, true)
	if out.Error != "" || out.Payload != "probe-123" {
		t.Fatalf("UDP result: %+v", out)
	}
}
func TestControlValidation(t *testing.T) {
	h := controlHandler("127.0.0.1:53", false)
	for _, tc := range []struct {
		method, body string
		status       int
	}{{"GET", "", 405}, {"POST", "{", 400}, {"POST", `{"domain":"selected.test","source":"wrong"}`, 400}, {"POST", `{"domain":"selected.test","port":-1}`, 400}} {
		r := httptest.NewRequest(tc.method, "/request", strings.NewReader(tc.body))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != tc.status {
			t.Fatalf("status %d expected %d", w.Code, tc.status)
		}
	}
}
