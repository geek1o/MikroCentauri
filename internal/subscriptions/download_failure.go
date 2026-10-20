package subscriptions

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

// Download errors contain fixed codes only: URL paths, queries, DNS answers and
// TLS error strings can contain private subscription credentials or metadata.
type downloadFailure string

func (e downloadFailure) Error() string { return "subscription download: " + string(e) }

// SafeFailureCode also sanitizes projections of old or externally supplied state.
func SafeFailureCode(code string) string {
	switch code {
	case "proxy_unavailable", "invalid_url", "dns_failed", "destination_refused", "connect_failed", "timeout", "tls_failed", "redirect_refused", "http_error", "body_invalid", "request_failed":
		return code
	default:
		return ""
	}
}

func downloadFailureCode(err error) string {
	var fixed downloadFailure
	if errors.As(err, &fixed) {
		return SafeFailureCode(string(fixed))
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "tls_failed"
	}
	return "request_failed"
}
