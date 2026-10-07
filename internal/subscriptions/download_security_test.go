package subscriptions

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The local DNS fixture makes mixed answers and changes between lookups observable
// without relying on a public resolver or a routable private destination.
func securityDNS(t *testing.T, answers func(int32) []netip.Addr) *atomic.Int32 {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buffer := make([]byte, 4096)
		for {
			size, peer, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			query := append([]byte(nil), buffer[:size]...)
			if len(query) < 17 {
				continue
			}
			end := 12
			for end < len(query) && query[end] != 0 {
				end += int(query[end]) + 1
			}
			end += 5
			if end > len(query) {
				continue
			}
			var addresses []netip.Addr
			if binary.BigEndian.Uint16(query[end-4:end-2]) == 1 {
				addresses = answers(queries.Add(1))
			}
			response := make([]byte, 12)
			copy(response[:2], query[:2])
			response[2], response[3] = 0x81, 0x80
			binary.BigEndian.PutUint16(response[4:6], 1)
			binary.BigEndian.PutUint16(response[6:8], uint16(len(addresses)))
			response = append(response, query[12:end]...)
			for _, address := range addresses {
				ipv4 := address.As4()
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				response = append(response, ipv4[:]...)
			}
			_, _ = socket.WriteTo(response, peer)
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", socket.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = original; socket.Close(); <-stopped })
	return &queries
}

func securityServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	if err := server.Certificate().VerifyHostname("example.com"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, roots
}

func TestSecurityMixedDNSAnswersRefusedBeforeHTTP(t *testing.T) {
	var hits atomic.Int32
	server, roots := securityServer(t, func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte("valid fixture")) })
	queries := securityDNS(t, func(int32) []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.9.8.7")}
	})
	manager := securityManager(t, roots)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	if _, err := manager.download(context.Background(), "https://example.com:"+port); err == nil || hits.Load() != 0 || queries.Load() == 0 {
		t.Fatal("mixed allowed/private answer was not refused before HTTP")
	}
}

func TestSecurityDNSRecheckedWithoutDialRebinding(t *testing.T) {
	var hits atomic.Int32
	server, roots := securityServer(t, func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte("valid fixture")) })
	queries := securityDNS(t, func(count int32) []netip.Addr {
		if count == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		return []netip.Addr{netip.MustParseAddr("10.9.8.7")}
	})
	manager := securityManager(t, roots)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	target := "https://example.com:" + port
	if _, err := manager.download(context.Background(), target); err != nil || hits.Load() != 1 || queries.Load() != 1 {
		t.Fatal("first validated answer was not pinned for the HTTP dial", err)
	}
	if _, err := manager.download(context.Background(), target); err == nil || hits.Load() != 1 || queries.Load() != 2 {
		t.Fatal("next download reused authority after DNS changed to a private address")
	}
}

func TestSecurityRedirectDestinationAndTLSDowngradeRefused(t *testing.T) {
	for _, scenario := range []string{"private destination", "TLS downgrade"} {
		t.Run(scenario, func(t *testing.T) {
			var destinationHits atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { destinationHits.Add(1) }))
			defer destination.Close()
			target := destination.URL
			if scenario == "private destination" {
				listener, err := net.Listen("tcp", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				private := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { destinationHits.Add(1) }))
				private.Listener.Close()
				private.Listener = listener
				private.StartTLS()
				if err := private.Certificate().VerifyHostname("::1"); err != nil {
					t.Fatal(err)
				}
				defer private.Close()
				target = private.URL
			}
			origin, roots := securityServer(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusFound) })
			manager := securityManager(t, roots)
			if _, err := manager.download(context.Background(), origin.URL); err == nil || destinationHits.Load() != 0 {
				t.Fatal("unsafe redirect destination accepted")
			}
		})
	}
}

func securityManager(t *testing.T, roots *x509.CertPool) *Manager {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(filepath.Join(directory, "sets"), Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, RootCAs: roots, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
