package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreconfig"
)

func bootstrapFixture(t *testing.T) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err := os.Mkdir(data, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "generated-secret")
	if err := os.WriteFile(secret, []byte("generated-unique-password-123456"), 0444); err != nil {
		t.Fatal(err)
	}
	return data, secret
}

func TestBootstrapPrivateTLSDirectAndAuthPreservation(t *testing.T) {
	data, secret := bootstrapFixture(t)
	if err := bootstrapApp(data, "172.18.0.20", "192.168.88.1", "8443", secret); err != nil {
		t.Fatal(err)
	}
	s, err := loadAppSettings(filepath.Join(data, "bootstrap/app.json"))
	if err != nil || s.PublicOrigin != "https://192.168.88.1:8443" || s.RouterConfig != "" || s.RuntimeProfile != "" {
		t.Fatal(s, err)
	}
	for _, path := range []string{data, filepath.Join(data, "bootstrap")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("unprotected directory", path, err)
		}
	}
	for _, path := range []string{s.Model, s.TLSKey, s.TLSCert, s.PasswordFile, filepath.Join(data, "bootstrap/app.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unprotected bootstrap file", path, err)
		}
	}
	modelBytes, _ := os.ReadFile(s.Model)
	model, err := coreconfig.Decode(modelBytes)
	if err != nil || len(model.Endpoints) != 0 || model.DefaultOutbound != "direct" || len(model.DNS.SelectedDomains) != 0 {
		t.Fatal("bootstrap granted proxy authority", err)
	}
	certBytes, _ := os.ReadFile(s.TLSCert)
	block, _ := pem.Decode(certBytes)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || leaf.VerifyHostname("172.18.0.20") != nil || leaf.VerifyHostname("192.168.88.1") != nil {
		t.Fatal("TLS names missing", err)
	}
	if err := initializeAppAuth(filepath.Join(data, "api"), s.PasswordFile); err != nil {
		t.Fatal(err)
	}
	auth, err := api.OpenAuth(filepath.Join(data, "api"))
	if err != nil {
		t.Fatal(err)
	}
	_, status := auth.Login("generated-unique-password-123456")
	server, serverErr := api.New(api.Options{Directory: filepath.Join(data, "api"), Auth: auth, Model: model, Origin: s.PublicOrigin, Clients: []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")}})
	if serverErr != nil {
		t.Fatal("first-start management server unavailable", serverErr)
	}
	for _, path := range []string{"/", "/api/v1/health/live"} {
		request := httptest.NewRequest(http.MethodGet, s.PublicOrigin+path, nil)
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		request.RemoteAddr = "192.168.88.10:30000"
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != 200 {
			t.Fatal("first-start UI or liveness unavailable", path, response.Code, response.Body.String())
		}
	}
	auth.Close()
	if status != 200 {
		t.Fatal("generated password unusable", status)
	}
	before, _ := os.ReadFile(filepath.Join(data, "api/auth.json"))
	os.Remove(secret)
	if err := bootstrapApp(data, "invalid", "invalid", "invalid", secret); err != nil {
		t.Fatal("existing installation depends on regenerated placeholders", err)
	}
	if err := initializeAppAuth(filepath.Join(data, "api"), s.PasswordFile); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(data, "api/auth.json"))
	if string(before) != string(after) {
		t.Fatal("authentication reset on restart")
	}
}

func TestBootstrapRejectsUnsafeInputsWithoutCreatingState(t *testing.T) {
	for _, kind := range []string{"public-ip", "partial-state", "secret-symlink", "writable-secret", "short-secret"} {
		t.Run(kind, func(t *testing.T) {
			data, secret := bootstrapFixture(t)
			ip := "172.18.0.20"
			switch kind {
			case "public-ip":
				ip = "8.8.8.8"
			case "partial-state":
				os.WriteFile(filepath.Join(data, "previous-private-state"), []byte("keep"), 0600)
			case "secret-symlink":
				link := secret + "-link"
				os.Symlink(secret, link)
				secret = link
			case "writable-secret":
				os.Chmod(secret, 0644)
			case "short-secret":
				os.Chmod(secret, 0600)
				os.WriteFile(secret, []byte("short"), 0444)
				os.Chmod(secret, 0444)
			}
			if err := bootstrapApp(data, ip, "192.168.88.1", "8443", secret); err == nil {
				t.Fatal("unsafe bootstrap admitted")
			}
			if _, err := os.Stat(filepath.Join(data, "bootstrap/app.json")); !os.IsNotExist(err) {
				t.Fatal("partial configuration committed", err)
			}
		})
	}
}
