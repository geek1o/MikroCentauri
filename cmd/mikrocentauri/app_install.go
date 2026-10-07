package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/application"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/platform/routeros"
)

type appInstallExpected struct {
	AppName           string `json:"app_name"`
	ContainerName     string `json:"container_name,omitempty"`
	ImageReference    string `json:"image_reference"`
	ImageConfigSHA256 string `json:"image_config_sha256"`
}

type appInstallIdentity struct {
	RouterVersion string            `json:"router_version"`
	Architecture  string            `json:"architecture"`
	App           map[string]string `json:"app"`
	Container     map[string]string `json:"container"`
	VETH          map[string]string `json:"veth"`
	StateSource   string            `json:"state_source"`
}

type appInstallReview struct {
	SchemaVersion int                `json:"schema_version"`
	CreatedAt     time.Time          `json:"created_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Target        string             `json:"target"`
	Expected      appInstallExpected `json:"expected"`
	InputSHA256   string             `json:"input_sha256"`
	Identity      appInstallIdentity `json:"identity"`
	ManualAction  string             `json:"manual_action"`
	Readiness     bool               `json:"readiness"`
}

var appNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var appSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var appObjectIDPattern = regexp.MustCompile(`^\*[0-9A-Fa-f]+$`)

func validateAppInstallExpected(expected appInstallExpected) error {
	if !appNamePattern.MatchString(expected.AppName) || (expected.ContainerName != "" && !appNamePattern.MatchString(expected.ContainerName)) || !appSHA256Pattern.MatchString(expected.ImageConfigSHA256) {
		return errors.New("invalid App name, container name or expected OCI config SHA256")
	}
	parts := strings.Split(expected.ImageReference, "@sha256:")
	if len(parts) != 2 || !appSHA256Pattern.MatchString(parts[1]) || len(parts[0]) > 1024 || strings.ContainsAny(parts[0], " \t\n\r?#@\\") {
		return errors.New("immutable credential-free expected image reference required")
	}
	base := parts[0]
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.Path == "" || u.Scheme != "https" {
		return errors.New("invalid expected image registry reference")
	}
	return nil
}

func appBundlePath(bundle, remote string) (string, error) {
	if !canonicalAppPath(remote) || !strings.HasPrefix(remote, "/data/") {
		return "", errors.New("installation input must map to a canonical /data path")
	}
	path := filepath.Join(bundle, strings.TrimPrefix(remote, "/data/"))
	if !beneathAppData(bundle, path) {
		return "", errors.New("installation bundle path escaped")
	}
	return path, nil
}

// The bundle represents remote /data on the operator's host. It permits a Mac
// review without creating /data or weakening the protected-input contract.
func appInstallInputs(settingsPath, bundle string, now time.Time) (appSettings, application.Profile, string, error) {
	var emptyProfile application.Profile
	if !canonicalAppPath(bundle) {
		return appSettings{}, emptyProfile, "", errors.New("absolute protected bundle-directory required")
	}
	info, e := os.Lstat(bundle)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return appSettings{}, emptyProfile, "", errors.New("installation bundle-directory must exist as a private 0700 directory")
	}
	initialSettings, e := readRouterFile(settingsPath, 65536, true)
	if e != nil {
		return appSettings{}, emptyProfile, "", e
	}
	s, e := loadAppSettings(settingsPath)
	if e != nil {
		return s, emptyProfile, "", e
	}
	if s.DataDirectory != "/data" || s.RuntimeProfile == "" || s.RouterConfig == "" {
		return s, emptyProfile, "", errors.New("native installation review requires /data and paired runtime/router inputs")
	}
	inputs := map[string]string{}
	read := func(name, path string, private bool, limit int64) ([]byte, error) {
		mapped, err := appBundlePath(bundle, path)
		if err != nil {
			return nil, err
		}
		data, err := readRouterFile(mapped, limit, private)
		if err != nil {
			return nil, errors.New("protected installation bundle input unavailable")
		}
		digest := sha256.Sum256(data)
		inputs[name+":"+path] = hex.EncodeToString(digest[:])
		return data, nil
	}
	settings, e := readRouterFile(settingsPath, 65536, true)
	if e != nil {
		return s, emptyProfile, "", e
	}
	if !bytes.Equal(settings, initialSettings) {
		return s, emptyProfile, "", errors.New("installation settings changed while reading")
	}
	settingsDigest := sha256.Sum256(settings)
	inputs["settings"] = hex.EncodeToString(settingsDigest[:])
	data, e := read("model", s.Model, true, 4<<20)
	if e != nil {
		return s, emptyProfile, "", e
	}
	model, e := coreconfig.Decode(data)
	if e != nil || !beneathAppData("/data", model.DNS.CachePath) {
		return s, emptyProfile, "", errors.New("invalid installation model")
	}
	data, e = read("runtime", s.RuntimeProfile, true, 1<<20)
	if e != nil {
		return s, emptyProfile, "", e
	}
	var profile application.Profile
	if uniqueJSON(data) != nil {
		return s, emptyProfile, "", errors.New("invalid installation runtime profile")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil || profile.Validate(model) != nil || !beneathAppData("/data", profile.Directory) || (profile.RuleSetDirectory != "" && profile.RuleSetDirectory != "/data/rulesets") {
		return s, emptyProfile, "", errors.New("invalid native installation profile or persistent directories")
	}
	data, e = read("router", s.RouterConfig, true, 65536)
	if e != nil {
		return s, emptyProfile, "", e
	}
	var connection routerConnection
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if uniqueJSON(data) != nil || decoder.Decode(&connection) != nil || connection.Username == "" || connection.Password == "" {
		return s, emptyProfile, "", errors.New("invalid protected container RouterOS connection")
	}
	u, e := url.Parse(connection.BaseURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSuffix(u.Path, "/") != "/rest" {
		return s, emptyProfile, "", errors.New("container RouterOS connection requires credential-free HTTPS /rest")
	}
	if connection.CAFile != "" {
		if _, e := read("router-ca", connection.CAFile, false, 1<<20); e != nil {
			return s, emptyProfile, "", e
		}
	}
	cert, e := read("tls-cert", s.TLSCert, false, 1<<20)
	if e != nil {
		return s, emptyProfile, "", e
	}
	key, e := read("tls-key", s.TLSKey, true, 1<<20)
	if e != nil {
		return s, emptyProfile, "", e
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return s, emptyProfile, "", errors.New("invalid installation TLS key/certificate")
	}
	ca := cert
	if s.TLSCA != "" {
		ca, e = read("tls-ca", s.TLSCA, false, 1<<20)
		if e != nil {
			return s, emptyProfile, "", e
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return s, emptyProfile, "", errors.New("invalid installation TLS trust")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return s, emptyProfile, "", errors.New("invalid installation TLS certificate")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return s, emptyProfile, "", errors.New("invalid installation certificate chain")
		}
		intermediates.AddCert(certificate)
	}
	host, _, _ := net.SplitHostPort(s.Listen)
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: host, CurrentTime: now}); e != nil {
		return s, emptyProfile, "", errors.New("installation TLS certificate must currently verify for literal listener IP")
	}
	if s.PublicOrigin != "" {
		origin, e := url.Parse(s.PublicOrigin)
		if e != nil {
			return s, emptyProfile, "", errors.New("invalid installation public origin")
		}
		if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: origin.Hostname(), CurrentTime: now}); e != nil {
			return s, emptyProfile, "", errors.New("installation TLS certificate must also verify for public origin host")
		}
	}
	// Password-file removal after bootstrap is valid; do not read or hash it.
	encoded, _ := json.Marshal(inputs)
	digest := sha256.Sum256(encoded)
	return s, profile, hex.EncodeToString(digest[:]), nil
}

func singleAppInstallRow(rows []map[string]string, matches func(map[string]string) bool) (map[string]string, error) {
	var found map[string]string
	for _, row := range rows {
		if matches(row) {
			if found != nil {
				return nil, errors.New("ambiguous App installation identity")
			}
			found = row
		}
	}
	if found == nil || !appObjectIDPattern.MatchString(found[".id"]) {
		return nil, errors.New("App installation resource not uniquely present")
	}
	return found, nil
}

func appInstallIdentityFor(snapshot routeros.AppInstallation, expected appInstallExpected, settings appSettings, profile application.Profile) (appInstallIdentity, bool, error) {
	var identity appInstallIdentity
	if e := validateAppInstallExpected(expected); e != nil {
		return identity, false, e
	}
	if snapshot.Resource["version"] != "7.24.5 (stable)" || snapshot.Resource["architecture-name"] != "x86_64" {
		return identity, false, errors.New("installation staging currently accepts only pinned RouterOS 7.24.5 x86_64")
	}
	app, e := singleAppInstallRow(snapshot.Apps, func(row map[string]string) bool { return row["name"] == expected.AppName })
	if e != nil {
		return identity, false, e
	}
	if app["disabled"] != "true" || app["running"] != "false" {
		return identity, false, errors.New("installation review requires App disabled and not running")
	}
	container, e := singleAppInstallRow(snapshot.Containers, func(row map[string]string) bool {
		return row["interface"] == app["interface"] && (expected.ContainerName == "" || row["name"] == expected.ContainerName)
	})
	if e != nil {
		return identity, false, e
	}
	if container["stopped"] != "true" || (container["running"] != "" && container["running"] != "false") {
		return identity, false, errors.New("installation review requires generated container stopped")
	}
	if container["remote-image"] != expected.ImageReference || strings.TrimPrefix(container["image-id"], "sha256:") != expected.ImageConfigSHA256 || container["check-certificate"] != "true" {
		return identity, false, errors.New("generated container image or certificate-verification identity differs")
	}
	// RouterOS App supervisors persist command overrides independently from
	// YAML and the stopped container's current cmd. Native 7.24.5 READ format
	// inserts the generated container name; it differs from setter syntax.
	// Compare the complete known empty-command representation without splitting
	// colons (registry ports, HTTPS and sha256 all contain them).
	if container["name"] == "" || app["container-command-lines"] != "core:"+container["name"]+":"+expected.ImageReference {
		return identity, false, errors.New("App supervisor pending command override or unverified default command state")
	}
	if container["entrypoint"] != "" || container["cmd"] != "" || container["default-cmd"] != "" || container["default-entrypoint"] != "/usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json" {
		return identity, false, errors.New("generated container must retain production image entrypoint")
	}
	veth, e := singleAppInstallRow(snapshot.VETHs, func(row map[string]string) bool { return row["name"] == app["interface"] })
	if e != nil {
		return identity, false, e
	}
	address, e := netip.ParsePrefix(veth["address"])
	appIP, err := netip.ParseAddr(app["ip-address"])
	if e != nil || err != nil || !address.Addr().Is4() || !address.Addr().IsPrivate() || address.Addr() != appIP || veth["dhcp"] != "false" || veth["disabled"] != "false" {
		return identity, false, errors.New("generated App/VETH private static identity differs")
	}
	gateway, e := netip.ParseAddr(veth["gateway"])
	if e != nil || !gateway.Is4() || !address.Masked().Contains(gateway) || gateway == appIP {
		return identity, false, errors.New("generated VETH gateway differs from its subnet")
	}
	for _, listener := range []string{settings.Listen, profile.DNSListen, profile.ReadinessListen} {
		host, _, e := net.SplitHostPort(listener)
		if e != nil || host != appIP.String() {
			return identity, false, errors.New("operator API/DNS/readiness listeners must match generated App IP")
		}
	}
	root := container["root-dir"]
	if !canonicalAppPath(root) || !strings.HasSuffix(root, "/apps/"+expected.AppName+"/core_root") || app["required-mounts"] != "state" {
		return identity, false, errors.New("generated App root or state volume identity differs")
	}
	stateSource := filepath.Join(filepath.Dir(root), "state")
	stateMatches := 0
	for _, mount := range strings.Split(container["mount"], ",") {
		parts := strings.Split(mount, ":")
		if len(parts) != 3 {
			return identity, false, errors.New("unrecognized generated App mount syntax")
		}
		if parts[1] == "/data" {
			if parts[0] != stateSource || parts[2] != "rw" {
				return identity, false, errors.New("generated state mount is not exact persistent read-write /data")
			}
			stateMatches++
		}
		if strings.HasPrefix(parts[1], "/data/") {
			return identity, false, errors.New("generated mount shadows persistent data")
		}
	}
	if stateMatches != 1 {
		return identity, false, errors.New("generated container requires exactly one persistent state mount")
	}
	privileged := container["privileged"] == "true"
	if !privileged && container["privileged"] != "false" {
		return identity, false, errors.New("container privilege evidence unavailable")
	}
	// Privilege is the only planned operator change. Keep other exact identity
	// fields stable; the artifact never authorizes starting or steering traffic.
	stableContainer := map[string]string{}
	for key, value := range container {
		if key != "privileged" {
			stableContainer[key] = value
		}
	}
	stableApp := map[string]string{}
	for key, value := range app {
		if key != "container-command-lines" {
			stableApp[key] = value
		}
	}
	identity = appInstallIdentity{snapshot.Resource["version"], snapshot.Resource["architecture-name"], stableApp, stableContainer, veth, stateSource}
	return identity, privileged, nil
}

func sameAppInstallIdentity(left, right appInstallIdentity) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

func appInstallOperatorHash(routerFile, bundleInputHash string) (string, error) {
	data, e := readRouterFile(routerFile, 65536, true)
	if e != nil {
		return "", e
	}
	var connection routerConnection
	if privateJSON(routerFile, &connection, 65536) != nil {
		return "", errors.New("invalid protected operator RouterOS connection")
	}
	after, e := readRouterFile(routerFile, 65536, true)
	if e != nil || !bytes.Equal(data, after) {
		return "", errors.New("operator RouterOS connection changed while reading")
	}
	hash := sha256.New()
	hash.Write([]byte(bundleInputHash))
	hash.Write([]byte{0})
	hash.Write(data)
	if connection.CAFile != "" {
		certificate, e := readRouterFile(connection.CAFile, 1<<20, false)
		if e != nil {
			return "", errors.New("operator RouterOS CA unavailable")
		}
		hash.Write([]byte{0})
		hash.Write(certificate)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func appInstallOutputSafe(output, settingsFile, routerFile, bundle string, settings appSettings) bool {
	if !canonicalAppPath(output) || output == settingsFile || output == routerFile {
		return false
	}
	var operator routerConnection
	if privateJSON(routerFile, &operator, 65536) != nil || (operator.CAFile != "" && output == operator.CAFile) {
		return false
	}
	for _, remote := range []string{settings.Model, settings.RuntimeProfile, settings.RouterConfig, settings.TLSCert, settings.TLSKey, settings.TLSCA, settings.PasswordFile} {
		if remote == "" {
			continue
		}
		mapped, e := appBundlePath(bundle, remote)
		if e == nil && output == mapped {
			return false
		}
	}
	return true
}

func appInstallCommand(action string, args []string) error {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	routerFile := fs.String("router-config", "", "protected operator HTTPS RouterOS connection")
	settingsFile := fs.String("settings-file", "", "protected intended container app.json")
	bundleDirectory := fs.String("bundle-directory", "", "0700 local directory representing remote /data")
	appName := fs.String("app", "", "exact imported disabled App name")
	containerName := fs.String("container", "", "optional exact generated container name")
	imageReference := fs.String("image-ref", "", "exact immutable container remote-image")
	imageConfig := fs.String("image-config-sha256", "", "OCI config digest; not index or manifest digest")
	output := fs.String("out", "", "protected review output path")
	reviewPath := fs.String("review", "", "protected unexpired review to verify after manual privilege change")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || (action != "app-install-plan" && action != "app-install-verify") {
		return errors.New("unsupported installation command or arguments")
	}
	if *routerFile == "" || *settingsFile == "" || *bundleDirectory == "" {
		return errors.New("router-config, settings-file and bundle-directory required")
	}
	now := time.Now().UTC()
	settings, profile, inputHash, e := appInstallInputs(*settingsFile, *bundleDirectory, now)
	if e != nil {
		return e
	}
	client, target, e := connectRouter(*routerFile)
	if e != nil {
		return e
	}
	inputHash, e = appInstallOperatorHash(*routerFile, inputHash)
	if e != nil {
		return e
	}
	expected := appInstallExpected{*appName, *containerName, *imageReference, strings.TrimPrefix(*imageConfig, "sha256:")}
	var review appInstallReview
	if action == "app-install-verify" {
		if *reviewPath == "" || *output != "" || *appName != "" || *containerName != "" || *imageReference != "" || *imageConfig != "" {
			return errors.New("verify accepts review identity only, not replacement expectations")
		}
		if privateJSON(*reviewPath, &review, 1<<20) != nil || review.SchemaVersion != 1 || review.Readiness || review.Target != target || review.InputSHA256 != inputHash || !appSHA256Pattern.MatchString(review.InputSHA256) || review.CreatedAt.After(now) || !review.ExpiresAt.After(now) || review.ExpiresAt.Sub(review.CreatedAt) != 10*time.Minute {
			return errors.New("invalid, changed or expired installation review")
		}
		expected = review.Expected
	} else if !appInstallOutputSafe(*output, *settingsFile, *routerFile, *bundleDirectory, settings) || *reviewPath != "" {
		return errors.New("plan requires out and forbids review")
	}
	if e := validateAppInstallExpected(expected); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, e := client.InspectAppInstallation(ctx)
	if e != nil {
		return e
	}
	identity, privileged, e := appInstallIdentityFor(snapshot, expected, settings, profile)
	if e != nil {
		return e
	}
	manual := "/container set " + identity.Container[".id"] + " privileged=yes"
	if action == "app-install-plan" {
		if privileged {
			manual = "already privileged; do not mutate container"
		}
		review = appInstallReview{1, now, now.Add(10 * time.Minute), target, expected, inputHash, identity, manual, false}
		data, e := json.MarshalIndent(review, "", "  ")
		if e != nil {
			return e
		}
		if e := config.WriteAtomic(*output, append(data, '\n')); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"review_saved": true, "manual_action": manual, "app_disabled": true, "container_stopped": true, "readiness": false})
	}
	if !sameAppInstallIdentity(identity, review.Identity) {
		return errors.New("stale installation identity; create a new reviewed plan")
	}
	if !privileged {
		return errors.New("manual privilege stage not verified; App must remain disabled")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"staged_identity_verified": true, "privilege_flag_verified": true, "protected_input_hashes_verified": true, "app_disabled": true, "container_stopped": true, "readiness": false, "scope": "read-only staged identity; Linux ingress interface/TUN, installed private file bytes, external browser access and actual native owner readiness remain unverified"})
}
