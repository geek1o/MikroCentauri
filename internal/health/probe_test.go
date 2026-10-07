package health

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The fixture verifies domain-form CONNECT, then acts as the controlled canary.
func socksFixture(t *testing.T, greeting, reply []byte, status int, body string, stall bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		g := make([]byte, 3)
		if _, err = io.ReadFull(c, g); err != nil {
			return
		}
		if string(g) != string([]byte{5, 1, 0}) {
			t.Error("wrong method offer")
			return
		}
		if stall {
			_, _ = io.Copy(io.Discard, c)
			return
		}
		c.Write(greeting)
		if string(greeting) != string([]byte{5, 0}) {
			return
		}
		h := make([]byte, 5)
		if _, err = io.ReadFull(c, h); err != nil {
			return
		}
		if h[0] != 5 || h[1] != 1 || h[2] != 0 || h[3] != 3 {
			t.Errorf("wrong CONNECT header %v", h)
			return
		}
		dst := make([]byte, int(h[4])+2)
		if _, err = io.ReadFull(c, dst); err != nil {
			return
		}
		if string(dst[:len(dst)-2]) != "selected.test" || dst[len(dst)-2] != 0x1f || dst[len(dst)-1] != 0x90 {
			t.Errorf("wrong destination %v", dst)
			return
		}
		c.Write(reply)
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		defer req.Body.Close()
		if req.Host != "selected.test:8080" || req.URL.Path != "/control" {
			t.Errorf("wrong HTTP request %v", req)
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 %d Fixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
	}()
	return ln.Addr().String()
}
func TestHTTPProbeProtocolAndEgress(t *testing.T) {
	validReply := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	cases := []struct {
		name            string
		greeting, reply []byte
		status          int
		body            string
		pass            bool
	}{
		{"proxy", []byte{5, 0}, validReply, 200, `{"remote_ip":"10.77.0.10"}`, true},
		{"direct fallback", []byte{5, 0}, validReply, 200, `{"remote_ip":"10.77.0.1"}`, false},
		{"malformed canary", []byte{5, 0}, validReply, 200, `{`, false},
		{"oversized canary", []byte{5, 0}, validReply, 200, strings.Repeat("x", 4097), false},
		{"wrong status", []byte{5, 0}, validReply, 503, `{"remote_ip":"10.77.0.10"}`, false},
		{"authentication demanded", []byte{5, 2}, nil, 200, "", false},
		{"wrong SOCKS version", []byte{4, 0}, nil, 200, "", false},
		{"connect rejected", []byte{5, 0}, []byte{5, 5, 0, 1}, 200, "", false},
		{"bad reserved field", []byte{5, 0}, []byte{5, 0, 1, 1}, 200, "", false},
		{"bad bound address", []byte{5, 0}, []byte{5, 0, 0, 8}, 200, "", false},
		{"empty domain bound address", []byte{5, 0}, []byte{5, 0, 0, 3, 0}, 200, "", false},
		{"truncated bound address", []byte{5, 0}, []byte{5, 0, 0, 1, 127}, 200, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := socksFixture(t, tc.greeting, tc.reply, tc.status, tc.body, false)
			p, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: endpoint, URL: "http://selected.test:8080/control", ExpectedPeerIP: "10.77.0.10", Timeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Check(context.Background()); (err == nil) != tc.pass {
				t.Fatalf("pass=%t error=%v", tc.pass, err)
			}
		})
	}
}
func TestSOCKSStallContext(t *testing.T) {
	endpoint := socksFixture(t, nil, nil, 200, "", true)
	p, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: endpoint, URL: "http://selected.test:8080/control", ExpectedPeerIP: "10.77.0.10", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err = p.Check(ctx); err == nil {
		t.Fatal("stalled handshake accepted")
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancellation did not close handshake")
	}
}
func TestProbeConfigRejectsCredentials(t *testing.T) {
	_, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://secret:password@selected.test:8080/", ExpectedPeerIP: "10.77.0.10"})
	if err == nil || strings.Contains(err.Error(), "password") {
		t.Fatal("URL credentials must be rejected without echoing")
	}
}
