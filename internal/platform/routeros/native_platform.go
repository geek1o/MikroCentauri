package routeros

import "strings"

// NativePlatformCandidate is a deliberately narrow startup allowlist. Matching
// it permits kernel and ownership preflight; it never establishes readiness.
// In particular, ARM64 container capabilities are inspected rather than relying
// on the newer CHR-only container privileged property.
func NativePlatformCandidate(version, architecture, board string) bool {
	if (version == "7.24.5" || version == "7.24.5 (stable)") && architecture == "x86_64" && (board == "CHR" || strings.HasPrefix(board, "CHR ")) {
		return true
	}
	return version == "7.23.8 (long-term)" && architecture == "arm64" && board == "hAP ax^2"
}
