package routeros

import "testing"

func TestNativePlatformCandidate(t *testing.T) {
	for _, tc := range []struct {
		version, architecture, board string
		want                         bool
	}{
		{"7.24.5 (stable)", "x86_64", "CHR fixture", true},
		{"7.23.8 (long-term)", "arm64", "hAP ax^2", true},
		{"7.23.8 (long-term)", "arm64", "other", false},
		{"7.23.8", "arm64", "hAP ax^2", false},
		{"7.23.8 (long-term)", "x86_64", "CHR fixture", false},
		{"7.24beta1", "arm64", "hAP ax^2", false},
	} {
		if got := NativePlatformCandidate(tc.version, tc.architecture, tc.board); got != tc.want {
			t.Fatalf("%+v: %v", tc, got)
		}
	}
}
