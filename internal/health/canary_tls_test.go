package health

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A real TLS handshake passes through a SOCKS fixture. DNS is deliberately
// unavailable for the certificate name; CONNECT must retain the literal IP.
func TestLiteralCanaryKeepsTLSNameHostAndReviewedEgressSet(t *testing.T) {
	for _, name := range []string{"example.com", "wrong.example"} {
		t.Run(name, func(t *testing.T) {
			seenHost := make(chan string, 2)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenHost <- r.Host
				io.WriteString(w, "ip=203.0.113.9\n")
			}))
			defer server.Close()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				b := bufio.NewReader(c)
				g := make([]byte, 3)
				if _, err := io.ReadFull(b, g); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				h := make([]byte, 5)
				if _, err := io.ReadFull(b, h); err != nil || h[3] != 3 {
					return
				}
				dst := make([]byte, int(h[4])+2)
				if _, err := io.ReadFull(b, dst); err != nil {
					return
				}
				if string(dst[:len(dst)-2]) != "127.0.0.1" {
					t.Error("SOCKS destination was resolved or replaced")
					return
				}
				up, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				copied := make(chan struct{})
				go func() { io.Copy(up, b); up.Close(); close(copied) }()
				io.Copy(c, up)
				c.Close()
				<-copied
			}()
			peers := []string{"198.51.100.8", "::ffff:203.0.113.9"}
			p, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: ln.Addr().String(), URL: server.URL + "/trace", ServerName: name, ExpectedPeerIPs: peers, ResponseFormat: CanaryCloudflareTrace})
			if err != nil {
				t.Fatal(err)
			}
			peers[1] = "192.0.2.22" // Caller mutation must not change admission.
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			p.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
			err = p.Check(context.Background())
			if (err == nil) != (name == "example.com") {
				t.Fatal("TLS name or egress proof incorrect", err)
			}
			<-finished
			if name == "example.com" {
				_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
				if got := <-seenHost; got != "example.com:"+port {
					t.Fatal("wrong HTTP Host", got)
				}
			}
		})
	}
}

func TestCanaryTLSNameInputBoundaries(t *testing.T) {
	for _, name := range []string{"bad/name", "name:443", "user@name", "*.example.com", "127.0.0.1", "a..b", "-a.example", "a-.example", "a.example\r\nSecret: value", strings.Repeat("a", 64) + ".example"} {
		if _, _, err := CanaryTLS("https://192.0.2.4/trace", name); err == nil || strings.Contains(err.Error(), name) {
			t.Fatal("invalid TLS name accepted or echoed")
		}
	}
	for _, target := range []string{"http://192.0.2.4/", "https://named.example/", "https://0.0.0.0/", "https://user:secret@192.0.2.4/"} {
		if _, _, err := CanaryTLS(target, "example.com"); err == nil {
			t.Fatal("unpinned TLS target accepted")
		}
	}
	c, host, err := CanaryTLS("https://192.0.2.4:443/trace", "example.com")
	if err != nil || c.InsecureSkipVerify || c.MinVersion != tls.VersionTLS12 || c.ServerName != "example.com" || host != "example.com" {
		t.Fatal("unsafe TLS configuration")
	}
}

func TestExpectedCanaryPeerSetBoundariesAndDirectFallback(t *testing.T) {
	base := HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://literal.test/"}
	for _, peers := range [][]string{nil, {"not-an-ip"}, {"203.0.113.9", "::ffff:203.0.113.9"}, {"::%secret"}, {"0.0.0.0"}, make([]string, 33)} {
		base.ExpectedPeerIPs = peers
		if _, err := NewHTTPProbe(base); err == nil {
			t.Fatal("invalid expected peer set accepted")
		}
	}
	base.ExpectedPeerIP = "203.0.113.9"
	base.ExpectedPeerIPs = []string{"198.51.100.8"}
	if _, err := NewHTTPProbe(base); err == nil {
		t.Fatal("ambiguous single/set inputs accepted")
	}
	endpoint := socksFixture(t, []byte{5, 0}, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}, 200, `{"remote_ip":"10.77.0.1"}`, false)
	p, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: endpoint, URL: "http://selected.test:8080/control", ExpectedPeerIPs: []string{"10.77.0.10", "10.77.0.11"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Check(context.Background()) == nil {
		t.Fatal("DIRECT fallback passed proxy peer set")
	}
	if _, err := NewHTTPProbe(HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://127.0.0.1/control", ExpectedPeerIP: "127.0.0.1"}); err != nil {
		t.Fatal("legacy isolated loopback canary changed", err)
	}
}
