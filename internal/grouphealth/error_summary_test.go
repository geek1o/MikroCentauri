package grouphealth

import (
	"strings"
	"testing"
)

func TestChildErrorSummaryExposesOnlyFixedCategory(t *testing.T) {
	s := &errorSummary{}
	s.Write([]byte("private-token: lookup secret.example: exchange fai"))
	s.Write([]byte("led: i/o timeout; private-password"))
	if code := s.Code(); code != "dns_resolution_failed" || strings.Contains(code, "private") {
		t.Fatal("wrong or unredacted category", code)
	}
	if s.tail != "" {
		t.Fatal("raw diagnostic tail retained after classification")
	}
	s.Write([]byte("x509: certificate is valid for private.example, not private-ip"))
	if s.Code() != "tls_certificate_error" {
		t.Fatal("more specific failure lost")
	}
}

func TestHandshakeTimeoutIsDistinctFromPeerRejection(t *testing.T) {
	for text, want := range map[string]string{"TLS handshake timeout: private-host": "proxy_handshake_timeout", "TLS handshake: remote error: tls: handshake failure": "proxy_handshake_rejected"} {
		s := &errorSummary{}
		s.Write([]byte(text))
		if s.Code() != want {
			t.Fatal("handshake category lost")
		}
	}
}
