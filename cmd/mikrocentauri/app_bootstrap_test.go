package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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

func TestDirectHTTPSAppDoesNotDependOnCloudWebPlaceholders(t *testing.T) {
	for _, tc := range []struct{ name, access, port, expected string }{
		{"x86 private address", "192.168.88.1", "8443", "192.168.88.1"},
		{"missing web address", "", "8443", "172.18.0.20"},
		{"unresolved web placeholder", "[accessIP]", "8443", "172.18.0.20"},
		{"Cloud hostname", "router.sn.mynetname.net", "8443", "172.18.0.20"},
		{"explicit custom TCP mapping", "192.168.88.1", "9443", "192.168.88.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := directAppAccess("172.18.0.20", tc.access, tc.port)
			if err != nil || host != tc.expected || port != tc.port {
				t.Fatal(host, port, err)
			}
			data, secret := bootstrapFixture(t)
			t.Setenv("MC_DIRECT_HTTPS", "1")
			t.Setenv("MC_CONTAINER_IP", "172.18.0.20")
			t.Setenv("MC_ACCESS_IP", tc.access)
			t.Setenv("MC_ACCESS_PORT", "[accessPort]")
			t.Setenv("MC_DIRECT_ACCESS_PORT", tc.port)
			if err := bootstrapRouterOSApp(data, secret); err != nil {
				t.Fatal(err)
			}
			settings, err := loadAppSettings(filepath.Join(data, "bootstrap/app.json"))
			if err != nil || settings.PublicOrigin != "https://"+host+":"+port {
				t.Fatal(settings.PublicOrigin, err)
			}
			t.Setenv("MC_CONTAINER_IP", "invalid")
			os.Remove(secret)
			if err := bootstrapRouterOSApp(data, secret); err != nil {
				t.Fatal("existing state replaced", err)
			}
		})
	}
	for _, tc := range []struct{ container, access, port string }{
		{"8.8.8.8", "192.168.88.1", "8443"},
		{"172.18.0.20", "8.8.8.8", "8443"},
		{"172.18.0.20", "192.168.88.1", "[accessPort]"},
	} {
		if _, _, err := directAppAccess(tc.container, tc.access, tc.port); err == nil {
			t.Fatal("unsafe direct origin accepted")
		}
	}
}

func TestLegacyManifestBootstrapsWithoutCloudAccessPort(t *testing.T) {
	data, secret := bootstrapFixture(t)
	t.Setenv("MC_DIRECT_HTTPS", "")
	t.Setenv("MC_DIRECT_ACCESS_PORT", "")
	t.Setenv("MC_ACCESS_IP", "192.168.88.1")
	t.Setenv("MC_CONTAINER_IP", "172.18.0.20")
	t.Setenv("MC_ACCESS_PORT", "")
	if err := bootstrapRouterOSApp(data, secret); err != nil {
		t.Fatal(err)
	}
	settings, err := loadAppSettings(filepath.Join(data, "bootstrap/app.json"))
	if err != nil || settings.PublicOrigin != "https://192.168.88.1:8443" {
		t.Fatal(settings.PublicOrigin, err)
	}
}

func TestDirectBootstrapAppProcess(t *testing.T) {
	if path := os.Getenv("MIKROCENTAURI_TEST_DIRECT_BOOTSTRAP"); path != "" {
		settings, err := loadAppSettings(path)
		if err == nil {
			err = initializeAppAuth(filepath.Join(settings.DataDirectory, "api"), settings.PasswordFile)
		}
		if err == nil {
			err = apiCommand("api-serve", appServeArgs(settings))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDirectBootstrapStartsTLSWithoutCloudAndPreservesRestart(t *testing.T) {
	data, secret := bootstrapFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	listener.Close()
	t.Setenv("MC_DIRECT_HTTPS", "1")
	t.Setenv("MC_DIRECT_ACCESS_PORT", port)
	t.Setenv("MC_ACCESS_IP", "127.0.0.1")
	t.Setenv("MC_CONTAINER_IP", "172.18.0.20")
	t.Setenv("MC_ACCESS_PORT", "") // RouterOS without a Cloud/web mapping.
	if err := bootstrapRouterOSApp(data, secret); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(data, "bootstrap/app.json")
	settings, err := loadAppSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Relocate only the listener for this host test of bootstrap output and API
	// serve argv. Full app-run /data validation is exercised by container acceptance.
	settings.Listen = net.JoinHostPort("127.0.0.1", port)
	settingsBytes, _ := json.Marshal(settings)
	if err := os.WriteFile(settingsPath, settingsBytes, 0600); err != nil {
		t.Fatal(err)
	}
	var authBefore []byte
	for restart := 0; restart < 2; restart++ {
		command := exec.Command(os.Args[0], "-test.run", "^TestDirectBootstrapAppProcess$")
		command.Env = append(os.Environ(), "MIKROCENTAURI_TEST_DIRECT_BOOTSTRAP="+settingsPath)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		deadline := time.Now().Add(15 * time.Second)
		for appHealth(context.Background(), settings) != nil {
			if time.Now().After(deadline) {
				command.Process.Kill()
				<-done
				t.Fatal("direct bootstrap did not become live", output.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
		auth, err := os.ReadFile(filepath.Join(data, "api/auth.json"))
		if err != nil {
			t.Fatal(err)
		}
		if restart == 0 {
			authBefore = auth
		} else if !bytes.Equal(authBefore, auth) {
			t.Fatal("restart replaced authentication")
		}
		command.Process.Signal(os.Interrupt)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err, output.String())
			}
		case <-time.After(10 * time.Second):
			command.Process.Kill()
			<-done
			t.Fatal("startup child did not stop")
		}
	}
}
