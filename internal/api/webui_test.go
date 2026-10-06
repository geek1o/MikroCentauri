package api

import (
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedUIRetainsAdministrativeNetworkBoundary(t *testing.T) {
	s, _, _ := setup(t, nil)
	for _, test := range []struct {
		name, method, path, host, remote, origin string
		tls                                      bool
		status                                   int
	}{
		{"public shell", "GET", "/", "127.0.0.1:8443", "127.0.0.1:12", "", true, 200},
		{"head shell", "HEAD", "/", "127.0.0.1:8443", "127.0.0.1:12", "", true, 200},
		{"license notices", "GET", "/licenses.txt", "127.0.0.1:8443", "127.0.0.1:12", "", true, 200},
		{"plaintext", "GET", "/", "127.0.0.1:8443", "127.0.0.1:12", "", false, 403},
		{"foreign host", "GET", "/", "evil.example", "127.0.0.1:12", "", true, 403},
		{"foreign origin", "GET", "/", "127.0.0.1:8443", "127.0.0.1:12", "https://evil.example", true, 403},
		{"foreign socket", "GET", "/", "127.0.0.1:8443", "203.0.113.1:12", "", true, 403},
		{"query", "GET", "/?token=secret", "127.0.0.1:8443", "127.0.0.1:12", "", true, 403},
		{"mutation", "POST", "/", "127.0.0.1:8443", "127.0.0.1:12", "", true, 405},
		{"missing asset", "GET", "/assets/missing.js", "127.0.0.1:8443", "127.0.0.1:12", "", true, 404},
		{"traversal", "GET", "/assets/../../auth.json", "127.0.0.1:8443", "127.0.0.1:12", "", true, 404},
		{"encoded separator", "GET", "/assets/%2Ffile.js", "127.0.0.1:8443", "127.0.0.1:12", "", true, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, "https://127.0.0.1:8443"+test.path, nil)
			r.Host, r.RemoteAddr = test.host, test.remote
			if test.tls {
				r.TLS = &tls.ConnectionState{}
			} else {
				r.TLS = nil
			}
			r.Header.Set("Origin", test.origin)
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if test.status == 200 {
				csp := w.Header().Get("Content-Security-Policy")
				if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "connect-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
					t.Fatal(csp)
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("cached admin shell")
				}
				if test.method == "HEAD" && w.Body.Len() != 0 {
					t.Fatal("HEAD body")
				}
				if test.method == "GET" && !strings.Contains(w.Body.String(), "MikroCentauri") {
					t.Fatal("missing shell")
				}
			}
		})
	}
	if w := call(s, "GET", "/api/v1/config", "", nil); w.Code != 401 {
		t.Fatal("shell bypasses API auth")
	}
}
