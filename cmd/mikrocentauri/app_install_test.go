package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/application"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
)

func installFixture(t *testing.T) (appSettings, application.Profile, appInstallExpected, routeros.AppInstallation, string, string) {
	t.Helper()
	bundle, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(bundle, 0700)
	if e := os.Mkdir(filepath.Join(bundle, "bootstrap"), 0700); e != nil {
		t.Fatal(e)
	}
	endpoint, e := endpoints.ParseURI("trojan://installation-test-secret@example.org:443#fixture")
	if e != nil {
		t.Fatal(e)
	}
	model := coreconfig.Model{SchemaVersion: 2, Instance: "api-native", Mode: "hybrid", Endpoints: []endpoints.Endpoint{endpoint}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "10.77.0.20", FakeIPRange: "198.19.0.0/16", CachePath: "/data/runtime/cache.db"}}
	profile := application.Profile{Schema: 1, Directory: "/data/native", DNSListen: "172.18.0.22:5353", ReadinessListen: "172.18.0.22:9099", ObserverClient: "192.168.88.1", IngressInterface: "eth0", Table: 202, RulePriority: 1000, LocalRulePriority: 200, LANCIDR: "192.168.88.0/24", LANInterface: "bridge-lan", MappingChain: "mc-api-native-backup", MappingPlaceBefore: "*7", Capacity: 256, RealDNSAddress: "10.77.0.20:53", CanaryURL: "http://10.77.0.20:8080/ip", CanaryPeerIP: "10.77.0.1", Watchdog: routeros.WatchdogSpec{Instance: "api-native", Host: "172.18.0.22", Port: 9099, Interval: 2 * time.Second, Timeout: time.Second, SuccessThreshold: 3, LANLeaseCIDR: "192.168.88.0/24", Targets: []routeros.Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:api-native:route:fakeip", "disabled": "true", "dst-address": "198.19.0.0/16", "gateway": "172.18.0.22", "routing-table": "main"}}}}}
	if e := profile.Validate(model); e != nil {
		t.Fatal(e)
	}
	settings := appSettings{SchemaVersion: 1, DataDirectory: "/data", Listen: "172.18.0.22:8443", AllowClients: []string{"192.168.88.0/24"}, Model: "/data/bootstrap/model.json", RuntimeProfile: "/data/bootstrap/runtime.json", RouterConfig: "/data/bootstrap/router.json", TLSCert: "/data/bootstrap/server.crt", TLSKey: "/data/bootstrap/server.key"}
	writeJSON := func(name string, value any) {
		data, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(bundle, "bootstrap", name), data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeJSON("model.json", model)
	writeJSON("runtime.json", profile)
	writeJSON("app.json", settings)
	writeJSON("router.json", routerConnection{BaseURL: "https://172.18.0.1/rest", Username: "fixture", Password: "protected-install-router-secret"})
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("172.18.0.22")}, DNSNames: []string{"router.example"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(bundle, "bootstrap", "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(bundle, "bootstrap", "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0400); e != nil {
		t.Fatal(e)
	}
	expected := appInstallExpected{AppName: "mikrocentauri", ImageReference: "https://registry.example/mikrocentauri@sha256:" + strings.Repeat("a", 64), ImageConfigSHA256: strings.Repeat("b", 64)}
	snapshot := routeros.AppInstallation{Resource: map[string]string{"version": "7.24.5 (stable)", "architecture-name": "x86_64", "board-name": "CHR fixture"}, Apps: []map[string]string{{".id": "*A", "name": "mikrocentauri", "interface": "veth-app-mikrocentauri", "ip-address": "172.18.0.22", "required-mounts": "state", "disabled": "true", "running": "false", "firewall-redirects": "8443:8443:tcp:api-secure"}}, Containers: []map[string]string{{".id": "*B", "name": "app-mikrocentauri", "interface": "veth-app-mikrocentauri", "root-dir": "/pcie1/apps/mikrocentauri/core_root", "remote-image": expected.ImageReference, "image-id": expected.ImageConfigSHA256, "mount": "/pcie1/apps/mikrocentauri/state:/data:rw", "privileged": "false", "stopped": "true", "check-certificate": "true", "default-entrypoint": "/usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json"}}, VETHs: []map[string]string{{".id": "*C", "name": "veth-app-mikrocentauri", "address": "172.18.0.22/24", "gateway": "172.18.0.1", "dhcp": "false", "disabled": "false"}}}
	snapshot.Apps[0]["container-command-lines"] = "core:" + snapshot.Containers[0]["name"] + ":" + expected.ImageReference
	return settings, profile, expected, snapshot, filepath.Join(bundle, "bootstrap", "app.json"), bundle
}

func cloneInstallSnapshot(t *testing.T, snapshot routeros.AppInstallation) routeros.AppInstallation {
	t.Helper()
	data, _ := json.Marshal(snapshot)
	var clone routeros.AppInstallation
	if e := json.Unmarshal(data, &clone); e != nil {
		t.Fatal(e)
	}
	return clone
}

func TestAppInstallExpectedRegistryRequiresHTTPS(t *testing.T) {
	expected := appInstallExpected{AppName: "mikrocentauri", ImageReference: "https://registry.example/mikrocentauri@sha256:" + strings.Repeat("a", 64), ImageConfigSHA256: strings.Repeat("b", 64)}
	if e := validateAppInstallExpected(expected); e != nil {
		t.Fatal(e)
	}
	for _, reference := range []string{"http://registry.example/mikrocentauri", "ftp://registry.example/mikrocentauri", "https://secret:password@registry.example/mikrocentauri"} {
		candidate := expected
		candidate.ImageReference = reference + "@sha256:" + strings.Repeat("a", 64)
		if e := validateAppInstallExpected(candidate); e == nil {
			t.Fatal("unsafe registry reference accepted")
		}
	}
	expected.ImageReference = "registry.example/mikrocentauri@sha256:" + strings.Repeat("a", 64)
	if e := validateAppInstallExpected(expected); e != nil {
		t.Fatal("implicit HTTPS registry rejected", e)
	}
}

func TestAppInstallMappedProtectedInputsAndTLS(t *testing.T) {
	_, _, _, _, settings, bundle := installFixture(t)
	s, p, fingerprint, e := appInstallInputs(settings, bundle, time.Now())
	if e != nil || !appSHA256Pattern.MatchString(fingerprint) || p.Directory != "/data/native" || s.Listen != "172.18.0.22:8443" {
		t.Fatal("valid local /data bundle rejected", e)
	}
	for _, remote := range []string{"/data", "/data/../secret", "/elsewhere/key", "/data-peer/key", "relative"} {
		if _, e := appBundlePath(bundle, remote); e == nil {
			t.Fatal("escaped mapping accepted", remote)
		}
	}
	s.PublicOrigin = "https://router.example:8443"
	data, _ := json.Marshal(s)
	if e := os.WriteFile(settings, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := appInstallInputs(settings, bundle, time.Now()); e != nil {
		t.Fatal("two-SAN TLS rejected", e)
	}
	s.PublicOrigin = "https://foreign.example:8443"
	data, _ = json.Marshal(s)
	if e := os.WriteFile(settings, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := appInstallInputs(settings, bundle, time.Now()); e == nil {
		t.Fatal("missing public-host SAN accepted")
	}
	s.PublicOrigin = ""
	data, _ = json.Marshal(s)
	os.WriteFile(settings, data, 0600)
	if e := os.Chmod(filepath.Join(bundle, "bootstrap", "server.key"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := appInstallInputs(settings, bundle, time.Now()); e == nil {
		t.Fatal("public TLS key accepted")
	}
}

func TestAppInstallIdentityRejectsForeignRunningImagesAndVolumes(t *testing.T) {
	s, profile, expected, snapshot, _, _ := installFixture(t)
	identity, privileged, e := appInstallIdentityFor(snapshot, expected, s, profile)
	if e != nil || privileged || identity.Container[".id"] != "*B" {
		t.Fatal("valid staged identity denied", e)
	}
	for name, mutate := range map[string]func(*routeros.AppInstallation){
		"running App":                func(v *routeros.AppInstallation) { v.Apps[0]["disabled"] = "false" },
		"running container":          func(v *routeros.AppInstallation) { v.Containers[0]["stopped"] = "false" },
		"foreign interface":          func(v *routeros.AppInstallation) { v.Containers[0]["interface"] = "foreign" },
		"foreign image":              func(v *routeros.AppInstallation) { v.Containers[0]["remote-image"] = "https://foreign/secret" },
		"manifest instead config":    func(v *routeros.AppInstallation) { v.Containers[0]["image-id"] = strings.Repeat("a", 64) },
		"certificate disabled":       func(v *routeros.AppInstallation) { v.Containers[0]["check-certificate"] = "false" },
		"command override":           func(v *routeros.AppInstallation) { v.Containers[0]["cmd"] = "private-secret-command" },
		"pending supervisor command": func(v *routeros.AppInstallation) { v.Apps[0]["container-command-lines"] += ":private-secret-command" },
		"absent supervisor command":  func(v *routeros.AppInstallation) { delete(v.Apps[0], "container-command-lines") },
		"empty supervisor command":   func(v *routeros.AppInstallation) { v.Apps[0]["container-command-lines"] = "" },
		"setter instead read syntax": func(v *routeros.AppInstallation) {
			v.Apps[0]["container-command-lines"] = "core:" + expected.ImageReference
		},
		"shell override": func(v *routeros.AppInstallation) { v.Containers[0]["entrypoint"] = "/bin/sh" },
		"foreign IP":     func(v *routeros.AppInstallation) { v.Apps[0]["ip-address"] = "172.18.0.23" },
		"foreign mount":  func(v *routeros.AppInstallation) { v.Containers[0]["mount"] = "/pcie1/apps/foreign/state:/data:rw" },
		"readonly mount": func(v *routeros.AppInstallation) {
			v.Containers[0]["mount"] = "/pcie1/apps/mikrocentauri/state:/data:ro"
		},
		"shadowed state":      func(v *routeros.AppInstallation) { v.Containers[0]["mount"] += ",/foreign:/data/bootstrap:rw" },
		"missing privilege":   func(v *routeros.AppInstallation) { delete(v.Containers[0], "privileged") },
		"version drift":       func(v *routeros.AppInstallation) { v.Resource["version"] = "7.26 (stable)" },
		"architecture drift":  func(v *routeros.AppInstallation) { v.Resource["architecture-name"] = "arm64" },
		"duplicate App":       func(v *routeros.AppInstallation) { v.Apps = append(v.Apps, v.Apps[0]) },
		"duplicate container": func(v *routeros.AppInstallation) { v.Containers = append(v.Containers, v.Containers[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			altered := cloneInstallSnapshot(t, snapshot)
			mutate(&altered)
			if _, _, e := appInstallIdentityFor(altered, expected, s, profile); e == nil || strings.Contains(e.Error(), "private-secret") {
				t.Fatal("unsafe identity accepted or leaked", e)
			}
		})
	}
	altered := cloneInstallSnapshot(t, snapshot)
	altered.Containers[0]["privileged"] = "true"
	fresh, privileged, e := appInstallIdentityFor(altered, expected, s, profile)
	if e != nil || !privileged || !sameAppInstallIdentity(identity, fresh) {
		t.Fatal("exact privilege stage disturbed identity", e)
	}
}

func TestAppInstallCLIReviewVerifyStaleInputsAndNoWrites(t *testing.T) {
	_, _, expected, snapshot, settings, bundle := installFixture(t)
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Query().Get(".proplist") == "" {
			t.Error("installer sent unsafe request", r.Method)
		}
		switch r.URL.Path {
		case "/rest/system/resource":
			json.NewEncoder(w).Encode(snapshot.Resource)
		case "/rest/app":
			json.NewEncoder(w).Encode(snapshot.Apps)
		case "/rest/container":
			json.NewEncoder(w).Encode(snapshot.Containers)
		case "/rest/interface/veth":
			json.NewEncoder(w).Encode(snapshot.VETHs)
		default:
			t.Error("unexpected installation resource", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ca := filepath.Join(bundle, "operator-ca.crt")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0644)
	connection := routerConnection{BaseURL: srv.URL + "/rest", Username: "fixture", Password: "operator-install-secret", CAFile: ca}
	data, _ := json.Marshal(connection)
	operatorConfig := filepath.Join(bundle, "operator-router.json")
	os.WriteFile(operatorConfig, data, 0600)
	review := filepath.Join(bundle, "review.json")
	common := []string{"-router-config", operatorConfig, "-settings-file", settings, "-bundle-directory", bundle}
	planArgs := append(append([]string{}, common...), "-app", expected.AppName, "-image-ref", expected.ImageReference, "-image-config-sha256", expected.ImageConfigSHA256, "-out", review)
	unsafeOutput := append(append([]string{}, planArgs[:len(planArgs)-1]...), settings)
	if e := appInstallCommand("app-install-plan", unsafeOutput); e == nil || requests != 0 {
		t.Fatal("review output could overwrite protected settings")
	}
	unsafeOutput = append(append([]string{}, planArgs[:len(planArgs)-1]...), ca)
	if e := appInstallCommand("app-install-plan", unsafeOutput); e == nil || requests != 0 {
		t.Fatal("review output could overwrite operator CA")
	}
	if e := appInstallCommand("app-install-plan", planArgs); e != nil {
		t.Fatal(e)
	}
	if requests != 4 {
		t.Fatal("plan did not inspect exact bounded resources", requests)
	}
	info, _ := os.Stat(review)
	if info.Mode().Perm() != 0600 {
		t.Fatal("review not private")
	}
	data, _ = os.ReadFile(review)
	for _, secret := range []string{"installation-test-secret", "operator-install-secret", "protected-install-router-secret", "PRIVATE KEY"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("installation review leaked credential")
		}
	}
	if strings.Contains(string(data), "container-command-lines") {
		t.Fatal("review retained raw App supervisor command line")
	}
	verify := append(append([]string{}, common...), "-review", review)
	if e := appInstallCommand("app-install-verify", verify); e == nil {
		t.Fatal("unprivileged installation verified")
	}
	snapshot.Containers[0]["privileged"] = "true"
	if e := appInstallCommand("app-install-verify", verify); e != nil {
		t.Fatal("manual privilege stage not verified", e)
	}
	snapshot.VETHs[0]["gateway"] = "172.18.0.2"
	if e := appInstallCommand("app-install-verify", verify); e == nil {
		t.Fatal("stale network identity verified")
	}
	snapshot.VETHs[0]["gateway"] = "172.18.0.1"
	var artifact appInstallReview
	if e := json.Unmarshal(data, &artifact); e != nil {
		t.Fatal(e)
	}
	artifact.CreatedAt = time.Now().Add(-11 * time.Minute).UTC()
	artifact.ExpiresAt = artifact.CreatedAt.Add(10 * time.Minute)
	expired, _ := json.Marshal(artifact)
	os.WriteFile(review, expired, 0600)
	before := requests
	if e := appInstallCommand("app-install-verify", verify); e == nil || requests != before {
		t.Fatal("expired review contacted native resources")
	}
	os.WriteFile(review, data, 0600)
	model := filepath.Join(bundle, "bootstrap", "model.json")
	original, _ := os.ReadFile(model)
	os.WriteFile(model, append(original, '\n'), 0600)
	if e := appInstallCommand("app-install-verify", verify); e == nil || requests != before {
		t.Fatal("changed protected model contacted native resources")
	}
	os.WriteFile(model, original, 0600)
	originalOperator, _ := os.ReadFile(operatorConfig)
	os.WriteFile(operatorConfig, append(originalOperator, '\n'), 0600)
	if e := appInstallCommand("app-install-verify", verify); e == nil || requests != before {
		t.Fatal("changed operator connection contacted native resources")
	}
}
