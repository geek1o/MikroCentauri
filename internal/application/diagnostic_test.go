package application

import (
	"context"
	"crypto/x509"
	"mikrocentauri.local/core/internal/health"
	"mikrocentauri.local/core/internal/singbox"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectCanaryFreshConnectionRedirectBoundAndResponseLimits(t *testing.T) {
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected++
		w.Write([]byte(`{"remote_ip":"192.0.2.1"}`))
	}))
	defer target.Close()
	for _, mode := range []string{"valid", "redirect", "malformed", "oversized", "status"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, 302)
				case "malformed":
					w.Write([]byte(`{"remote_ip":"private-secret"}`))
				case "oversized":
					w.Write([]byte(strings.Repeat("x", 4097)))
				case "status":
					w.WriteHeader(503)
				default:
					w.Write([]byte(`{"remote_ip":"192.0.2.2"}`))
				}
			}))
			defer server.Close()
			err := directCanary(context.Background(), server.URL)
			if (err == nil) != (mode == "valid") || redirected != 0 || err != nil && strings.Contains(err.Error(), "private-secret") {
				t.Fatal(mode, err, redirected)
			}
		})
	}
}
func TestSingBoxVersionObservedBoundedAndRedacted(t *testing.T) {
	for _, output := range []string{"sing-box version " + singbox.Version + "\nextra metadata\n", "sing-box version 0.0.0\nprivate-password", "too much"} {
		t.Run(output[:min(len(output), 20)], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture-binary")
			script := "#!/bin/sh\nprintf '%s\\n' '" + output + "'\n"
			if output == "too much" {
				script = "#!/bin/sh\nyes private-credential | head -c 50000\n"
			}
			if os.WriteFile(path, []byte(script), 0700) != nil {
				t.Fatal("fixture failed")
			}
			runtime := &Runtime{binary: path}
			v, e := runtime.SingBoxVersion(context.Background())
			valid := strings.HasPrefix(output, "sing-box version "+singbox.Version+"\n")
			if (e == nil) != valid || valid && v != singbox.Version || !valid && v != "" || e != nil && strings.Contains(e.Error(), "private-") {
				t.Fatal(v, e)
			}
		})
	}
}

func TestDiagnosticCanaryUsesProfileFormatAndTLSName(t *testing.T) {
	for _, mode := range []string{"valid", "duplicate peer", "legacy JSON", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" || !strings.HasPrefix(r.Host, "example.com:") {
					t.Error("TLS or HTTP name lost")
				}
				switch mode {
				case "duplicate peer":
					w.Write([]byte("ip=203.0.113.9\nip=203.0.113.9\n"))
				case "legacy JSON":
					w.Write([]byte(`{"remote_ip":"203.0.113.9"}`))
				case "redirect":
					http.Redirect(w, r, "https://example.com/private-secret", 302)
				default:
					w.Write([]byte("ip=203.0.113.9\n"))
				}
			}))
			defer server.Close()
			profile := Profile{CanaryURL: server.URL, CanaryServerName: "example.com", CanaryFormat: health.CanaryCloudflareTrace}
			tlsConfig, _, err := health.CanaryTLS(profile.CanaryURL, profile.CanaryServerName)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			tlsConfig.RootCAs = roots
			transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			err = canaryProfileRequest(context.Background(), client, profile)
			if (err == nil) != (mode == "valid") || err != nil && strings.Contains(err.Error(), "private-secret") {
				t.Fatal("diagnostic format failure", err)
			}
		})
	}
}
