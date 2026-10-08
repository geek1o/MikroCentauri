package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/application"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/platform/linuxbarrier"
)

// appSettings is an operator-provisioned private file, never an environment
// variable or HTTP input. The image contains no credentials or topology.
type appSettings struct {
	SchemaVersion  int      `json:"schema_version"`
	DataDirectory  string   `json:"data_directory,omitempty"`
	Listen         string   `json:"listen"`
	PublicOrigin   string   `json:"public_origin,omitempty"`
	AllowClients   []string `json:"allow_clients"`
	TLSCert        string   `json:"tls_cert"`
	TLSKey         string   `json:"tls_key"`
	TLSCA          string   `json:"tls_ca,omitempty"`
	Model          string   `json:"model"`
	RouterConfig   string   `json:"router_config,omitempty"`
	RuntimeProfile string   `json:"runtime_profile,omitempty"`
	PasswordFile   string   `json:"password_file,omitempty"`
}

func canonicalAppPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func beneathAppData(directory, path string) bool {
	if !canonicalAppPath(path) {
		return false
	}
	rel, e := filepath.Rel(directory, path)
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func loadAppSettings(path string) (appSettings, error) {
	var s appSettings
	if !canonicalAppPath(path) || privateJSON(path, &s, 65536) != nil {
		return s, errors.New("invalid private app settings")
	}
	if s.DataDirectory == "" {
		s.DataDirectory = "/data"
	}
	if s.SchemaVersion != 1 || !canonicalAppPath(s.DataDirectory) || !canonicalAppPath(s.Model) || !canonicalAppPath(s.TLSCert) || !canonicalAppPath(s.TLSKey) {
		return s, errors.New("invalid app settings paths or schema")
	}
	for _, optional := range []string{s.TLSCA, s.RouterConfig, s.RuntimeProfile, s.PasswordFile} {
		if optional != "" && !canonicalAppPath(optional) {
			return s, errors.New("invalid optional app input path")
		}
	}
	if (s.RouterConfig == "") != (s.RuntimeProfile == "") {
		return s, errors.New("app native startup requires both router_config and runtime_profile")
	}
	host, port, e := net.SplitHostPort(s.Listen)
	addr, err := netip.ParseAddr(host)
	if e != nil || err != nil || addr.IsUnspecified() || addr.Is4In6() || (!addr.IsLoopback() && !addr.IsPrivate()) {
		return s, errors.New("app listener must be literal private or loopback")
	}
	portNumber, portError := strconv.Atoi(port)
	if portError != nil || portNumber < 1 || portNumber > 65535 || strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return s, errors.New("invalid app listener port")
	}
	if !addr.IsLoopback() && len(s.AllowClients) == 0 {
		return s, errors.New("LAN app requires explicit client CIDRs")
	}
	if s.PublicOrigin != "" {
		s.PublicOrigin, e = api.CanonicalOrigin(s.PublicOrigin)
		if e != nil {
			return s, errors.New("invalid public HTTPS app origin")
		}
	}
	for _, client := range s.AllowClients {
		prefix, err := netip.ParsePrefix(client)
		if err != nil || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return s, errors.New("invalid app client network")
		}
	}
	return s, nil
}

func prepareApp(s appSettings) error {
	// Refuse invalid TLS/model/profile before creating durable authentication.
	if _, e := readRouterFile(s.TLSKey, 1<<20, true); e != nil {
		return errors.New("private app TLS key unavailable")
	}
	if _, e := readRouterFile(s.TLSCert, 1<<20, false); e != nil {
		return errors.New("app TLS certificate unavailable")
	}
	pair, e := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey)
	if e != nil || len(pair.Certificate) == 0 {
		return errors.New("invalid app TLS certificate/key")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	host, _, _ := net.SplitHostPort(s.Listen)
	origin := s.PublicOrigin
	if origin == "" {
		origin = "https://" + s.Listen
	}
	origin, originError := api.CanonicalOrigin(origin)
	originURL, _ := url.Parse(origin)
	if e != nil || originError != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) || leaf.VerifyHostname(host) != nil || leaf.VerifyHostname(originURL.Hostname()) != nil {
		return errors.New("current app certificate must cover listen IP and public origin hostname")
	}
	data, e := readRouterFile(s.Model, 4<<20, true)
	if e != nil {
		return errors.New("private app model unavailable")
	}
	model, e := coreconfig.Decode(data)
	if e != nil || !beneathAppData(s.DataDirectory, model.DNS.CachePath) {
		return errors.New("app model must use a persistent cache beneath data_directory")
	}
	if s.RuntimeProfile != "" {
		var profile application.Profile
		if privateJSON(s.RuntimeProfile, &profile, 1<<20) != nil || profile.Validate(model) != nil || !beneathAppData(s.DataDirectory, profile.Directory) || (profile.RuleSetDirectory != "" && profile.RuleSetDirectory != filepath.Join(s.DataDirectory, "rulesets")) {
			return errors.New("app runtime directories must remain beneath data_directory")
		}
		if _, _, e := connectRouter(s.RouterConfig); e != nil {
			return errors.New("private app RouterOS connection unavailable")
		}
	}
	if _, e := api.PrivateDirectory(s.DataDirectory); e != nil {
		return errors.New("app persistent data_directory must be a private0700 directory without symlinks")
	}
	return nil
}

func prepareAppKernel(s appSettings) (func() error, error) {
	var profile application.Profile
	data, e := readRouterFile(s.Model, 4<<20, true)
	if e != nil {
		return nil, errors.New("private app model unavailable")
	}
	model, e := coreconfig.Decode(data)
	if e != nil || privateJSON(s.RuntimeProfile, &profile, 1<<20) != nil || profile.Validate(model) != nil {
		return nil, errors.New("invalid native App kernel profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return linuxbarrier.PrepareAppKernel(ctx, linuxbarrier.AppKernelOptions{Interface: profile.IngressInterface,
		Table: profile.Table, RulePriority: profile.RulePriority, LocalRulePriority: profile.LocalRulePriority})
}

func initializeAppAuth(state, passwordFile string) error {
	if _, e := api.PrivateDirectory(state); e != nil {
		return e
	}
	_, e := os.Lstat(filepath.Join(state, "auth.json"))
	if e == nil {
		// Do not read the bootstrap password again, and never reset existing state.
		auth, err := api.OpenAuth(state)
		if err != nil {
			return errors.New("existing app authentication state unavailable")
		}
		auth.Close()
		return nil
	}
	if !os.IsNotExist(e) {
		return errors.New("app authentication state unavailable")
	}
	password, e := readRouterFile(passwordFile, 1024, true)
	if e != nil {
		return errors.New("first app startup requires private password_file")
	}
	defer clear(password)
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}
	if e := api.InitializeAuth(state, password); e != nil {
		return errors.New("app authentication initialization failed")
	}
	return nil
}

func appServeArgs(s appSettings) []string {
	clients := append([]string{}, s.AllowClients...)
	host, _, _ := net.SplitHostPort(s.Listen)
	ip := netip.MustParseAddr(host)
	// Permit the container's exact own address for local TLS liveness only.
	clients = append(clients, netip.PrefixFrom(ip, ip.BitLen()).String())
	args := []string{"-state", filepath.Join(s.DataDirectory, "api"), "-config", s.Model, "-listen", s.Listen, "-tls-cert", s.TLSCert, "-tls-key", s.TLSKey, "-allow-clients", strings.Join(clients, ","), "-sing-box", "/usr/bin/sing-box", "-ruleset-state", filepath.Join(s.DataDirectory, "rulesets")}
	if s.PublicOrigin != "" {
		args = append(args, "-public-origin", s.PublicOrigin)
	}
	if s.RuntimeProfile != "" {
		args = append(args, "-runtime-profile", s.RuntimeProfile, "-router-config", s.RouterConfig)
	}
	return args
}

func appHealth(ctx context.Context, s appSettings) error {
	ca := s.TLSCA
	if ca == "" {
		ca = s.TLSCert
	}
	certificate, e := readRouterFile(ca, 1<<20, false)
	if e != nil {
		return errors.New("app liveness certificate unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return errors.New("invalid app liveness trust")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", "https://"+s.Listen+"/api/v1/health/live", nil)
	if e != nil {
		return errors.New("invalid app liveness request")
	}
	origin := s.PublicOrigin
	if origin == "" {
		origin = "https://" + s.Listen
	}
	origin, e = api.CanonicalOrigin(origin)
	if e != nil {
		return errors.New("invalid app liveness origin")
	}
	req.Host = strings.TrimPrefix(origin, "https://")
	response, e := client.Do(req)
	if e != nil {
		return errors.New("app HTTPS liveness unavailable")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 513))
	var result struct {
		Live *bool `json:"live"`
	}
	if e != nil || len(data) > 512 || response.StatusCode != http.StatusOK || uniqueJSON(data) != nil {
		return errors.New("app API liveness failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Live == nil || !*result.Live {
		return errors.New("app API liveness failed")
	}
	return nil
}

func appCommand(action string, args []string) (result error) {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	settings := fs.String("config", "/data/bootstrap/app.json", "private operator-provisioned application settings")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || (action != "app-run" && action != "app-health") {
		return errors.New("unsupported app command or arguments")
	}
	if action == "app-run" && os.Getenv("MC_APP_BOOTSTRAP") == "1" && *settings == "/data/bootstrap/app.json" {
		if e := bootstrapRouterOSApp("/data", "/run/secrets/admin_password"); e != nil {
			return e
		}
	}
	s, e := loadAppSettings(*settings)
	if e != nil {
		return e
	}
	if action == "app-health" {
		return appHealth(context.Background(), s)
	}
	// RouterOS starts App processes with umask0000. sing-box creates its own
	// cache file, so explicit Go file modes alone cannot protect child outputs.
	// Establish the inherited process mask before initializing or starting owners.
	previousMask := syscall.Umask(0077)
	defer syscall.Umask(previousMask)
	if e := prepareApp(s); e != nil {
		return e
	}
	if s.RuntimeProfile != "" {
		cleanup, e := prepareAppKernel(s)
		if e != nil {
			return e
		}
		defer func() { result = errors.Join(result, cleanup()) }()
	}
	if e := initializeAppAuth(filepath.Join(s.DataDirectory, "api"), s.PasswordFile); e != nil {
		return e
	}
	if s.PublicOrigin != "" {
		fmt.Fprintln(os.Stdout, "MikroCentauri management URL:", s.PublicOrigin)
	}
	// Existing api-serve owns SIGTERM/SIGINT, child shutdown, subscription owner,
	// kernel preflight, native recovery and TLS. No shell or secondary daemon.
	return apiCommand("api-serve", appServeArgs(s))
}
