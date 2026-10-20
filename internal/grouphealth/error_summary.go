package grouphealth

import (
	"strings"
	"sync"
)

// errorSummary drains child stderr without retaining a diagnostic log. Only a
// fixed category is exposed; a bounded tail joins patterns across write chunks.
type errorSummary struct {
	mu         sync.Mutex
	tail, code string
	rank       int
}

func (s *errorSummary) Write(b []byte) (int, error) {
	n := len(b)
	if len(b) > 4096 {
		b = b[len(b)-4096:]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	text := s.tail + strings.ToLower(string(b))
	for _, rule := range []struct {
		pattern, code string
		rank          int
	}{
		{"x509:", "tls_certificate_error", 60}, {"certificate verify failed", "tls_certificate_error", 60},
		{"authentication failed", "proxy_authentication_failed", 50}, {"invalid user", "proxy_authentication_failed", 50},
		{"handshake timeout", "proxy_handshake_timeout", 48}, {"remote error: tls: handshake failure", "proxy_handshake_rejected", 48}, {"tls: bad record mac", "proxy_crypto_failed", 48}, {"reality verification", "proxy_handshake_failed", 45}, {"tls handshake", "proxy_handshake_failed", 40},
		{"lookup ", "dns_resolution_failed", 35}, {"exchange failed", "dns_resolution_failed", 35}, {"resolve domain", "dns_resolution_failed", 35},
		{"connection refused", "connection_refused", 30}, {"network is unreachable", "network_unreachable", 30},
		{"i/o timeout", "upstream_timeout", 20}, {"deadline exceeded", "upstream_timeout", 20},
		{"connection reset", "upstream_connection_reset", 15}, {"eof", "upstream_closed", 10},
	} {
		if rule.rank > s.rank && strings.Contains(text, rule.pattern) {
			s.rank = rule.rank
			s.code = rule.code
		}
	}
	if len(text) > 512 {
		text = text[len(text)-512:]
	}
	s.tail = text
	return n, nil
}
func (s *errorSummary) Code() string { s.mu.Lock(); defer s.mu.Unlock(); s.tail = ""; return s.code }
