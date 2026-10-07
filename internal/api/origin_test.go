package api

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestCanonicalOperatorOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Router.Example:443": "https://router.example",
		"https://192.168.88.1:08443": "https://192.168.88.1:8443",
		"https://[fd00::1]:443":      "https://[fd00::1]",
		"https://[fd00::1]:9443":     "https://[fd00::1]:9443",
	} {
		got, err := CanonicalOrigin(raw)
		if err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"http://router.example", "https://user:secret@router.example", "https://router.example/", "https://router.example?", "https://router.example#", "https://*.example", "https://router.example:", "https://router.example:65536", "https://router.example:0", "https://router..example", "https://-router.example", "https://router.example.", "https://0.0.0.0", "https://[::]", "https://[::ffff:127.0.0.1]", "https://[fe80::1%25eth0]"} {
		if got, err := CanonicalOrigin(raw); err == nil {
			t.Fatal("unsafe origin accepted", raw, got)
		}
	}
}

func TestAdvertisedOriginRetainsExactHostSocketAndAuthentication(t *testing.T) {
	s, _, _ := setup(t, nil)
	s.opts.Origin = "https://192.168.88.1:9443"
	for _, test := range []struct {
		name, path, host, origin, remote string
		status                           int
	}{
		{"advertised login shell", "/", "192.168.88.1:9443", "", "127.0.0.1:123", 200},
		{"advertised same-origin fetch", "/api/v1/health/live", "192.168.88.1:9443", s.opts.Origin, "127.0.0.1:123", 200},
		{"bind address is not another admin host", "/", "127.0.0.1:8443", "", "127.0.0.1:123", 403},
		{"cross-origin request", "/", "192.168.88.1:9443", "https://attacker.example", "127.0.0.1:123", 403},
		{"forwarded client is not trusted", "/", "192.168.88.1:9443", "", "203.0.113.1:123", 403},
		{"API still needs bearer", "/api/v1/config", "192.168.88.1:9443", s.opts.Origin, "127.0.0.1:123", 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://127.0.0.1:8443"+test.path, nil)
			r.TLS = &tls.ConnectionState{}
			r.Host, r.RemoteAddr = test.host, test.remote
			r.Header.Set("Origin", test.origin)
			r.Header.Set("Forwarded", "for=127.0.0.1;host=192.168.88.1:9443;proto=https")
			r.Header.Set("X-Forwarded-Host", "192.168.88.1:9443")
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
