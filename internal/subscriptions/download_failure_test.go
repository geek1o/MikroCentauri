package subscriptions

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDownloadFailuresAreClassifiedWithoutReplacingLastGoodNodes(t *testing.T) {
	for _, mode := range []string{"http_error", "timeout", "tls_failed", "body_invalid"} {
		t.Run(mode, func(t *testing.T) {
			failing := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !failing {
					w.Write([]byte(node))
					return
				}
				switch mode {
				case "http_error":
					w.WriteHeader(403)
				case "timeout":
					<-r.Context().Done()
				case "body_invalid":
					w.Write([]byte(strings.Repeat("x", 1025)))
				}
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			m, err := New(privateDir(t), Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Timeout: time.Second, MaxBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			spec := Spec{ID: "fixture", URL: server.URL + "/private-token?secret=never-disclose"}
			first, err := m.Refresh(context.Background(), spec)
			if err != nil {
				t.Fatal(err)
			}
			failing = true
			if mode == "tls_failed" {
				m.policy.RootCAs = x509.NewCertPool()
			}
			if mode == "timeout" {
				m.policy.Timeout = 50 * time.Millisecond
			}
			last, err := m.Refresh(context.Background(), spec)
			if err == nil || last.FailureCode != mode || last.LastSuccess != first.LastSuccess || len(last.Nodes) != 1 || last.Nodes[0].ID != first.Nodes[0].ID || strings.Contains(err.Error(), "private-token") || strings.Contains(err.Error(), "never-disclose") {
				t.Fatal("classification, redaction or LKG failure", mode, last.FailureCode, err)
			}
			loaded, err := m.Load(spec.ID)
			if err != nil || loaded.FailureCode != mode {
				t.Fatal("failure code was not persisted")
			}
			failing = false
			m.policy.RootCAs = roots
			m.policy.Timeout = time.Second
			recovered, err := m.Refresh(context.Background(), spec)
			if err != nil || recovered.FailureCode != "" || recovered.Failure != "" {
				t.Fatal("stale failure retained after success", err)
			}
		})
	}
}

func TestDownloadRefusedDestinationsAndRedirectsRemainFixedCodes(t *testing.T) {
	m, err := New(privateDir(t), Policy{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Refresh(context.Background(), Spec{ID: "fixture", URL: "https://127.0.0.1/private-secret"})
	if err == nil || s.FailureCode != "destination_refused" {
		t.Fatal("destination policy bypassed", err, s.FailureCode)
	}
	if SafeFailureCode("https://secret.example/token") != "" {
		t.Fatal("unknown state leaked into public code")
	}
}
