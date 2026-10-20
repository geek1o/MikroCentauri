package subscriptions

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyTunnelPinsLiteralAndRetainsBufferedBytes(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "203.0.113.9:443" || r.Header.Get("Proxy-Authorization") != "Basic Zml4dHVyZTpwcml2YXRlLXBhc3N3b3Jk" {
			t.Error("invalid literal/authenticated CONNECT")
			w.WriteHeader(407)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\nfixture-bytes")
		buffer := make([]byte, 1)
		c.Read(buffer)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("fixture", "private-password")
	dial, err := HTTPProxyDialer(u)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := dial(ctx, "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b := make([]byte, len("fixture-bytes"))
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "fixture-bytes" {
		t.Fatal("buffered tunnel data lost", err)
	}
}

func TestProxyTunnelInputBoundsCancellationAndRedaction(t *testing.T) {
	for _, raw := range []string{"http://user:private-password@proxy.example:80", "https://user:private-password@127.0.0.1:80", "http://127.0.0.1:80", "http://user:private-password@127.0.0.1:80/path"} {
		u, _ := url.Parse(raw)
		_, err := HTTPProxyDialer(u)
		if err == nil || strings.Contains(err.Error(), "private-password") {
			t.Fatal("unsafe proxy accepted or echoed")
		}
	}
	for _, mode := range []string{"oversized", "authentication", "stall"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				http.ReadRequest(bufio.NewReader(c))
				switch mode {
				case "oversized":
					io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Private: "+strings.Repeat("secret", 4000))
				case "authentication":
					io.WriteString(c, "HTTP/1.1 407 Authentication required\r\nContent-Length: 0\r\n\r\n")
				case "stall":
					io.Copy(io.Discard, c)
				}
			}()
			u := &url.URL{Scheme: "http", Host: ln.Addr().String(), User: url.UserPassword("fixture", "private-password")}
			dial, err := HTTPProxyDialer(u)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			started := time.Now()
			c, err := dial(ctx, "tcp", "203.0.113.9:443")
			if c != nil {
				c.Close()
			}
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private-password") || time.Since(started) > 500*time.Millisecond {
				t.Fatal("tunnel bounds/redaction failure", err)
			}
			<-done
		})
	}
}

func TestProxyDownloaderStillRefusesPrivateDNSBeforeTunnel(t *testing.T) {
	queries := securityDNS(t, func(int32) []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.9.8.7")} })
	manager, err := New(privateDir(t), Policy{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	_, err = manager.RefreshVia(context.Background(), Spec{ID: "fixture", URL: "https://example.com/private-token", ProxyNode: strings.Repeat("a", 64)}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		t.Error("forbidden address reached proxy")
		return nil, context.Canceled
	})
	if err == nil || dials.Load() != 0 || queries.Load() == 0 {
		t.Fatal("proxy bypassed destination policy", err)
	}
}
