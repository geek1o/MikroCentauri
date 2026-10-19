package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/platform/routeros"
)

// RouterSetupInput is write-only. No credential or certificate body is returned
// by status, diagnostics, safe backup, logs or installation reviews.
type RouterSetupInput struct {
	BaseURL        string `json:"base_url"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	CertificatePEM string `json:"certificate_pem"`
}
type RouterSetupStatus struct {
	Configured        bool   `json:"configured"`
	Editable          bool   `json:"editable"`
	BaseURL           string `json:"base_url"`
	Username          string `json:"username"`
	HasPassword       bool   `json:"has_password"`
	CertificateSHA256 string `json:"certificate_sha256"`
	NativeConnected   bool   `json:"native_connected"`
}
type RouterSetupResult struct {
	Saved   bool              `json:"saved"`
	Status  RouterSetupStatus `json:"status"`
	Router  RouterSnapshot    `json:"router"`
	Network routeros.Network  `json:"network"`
}
type SetupCheck struct {
	ID      string `json:"id"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}
type SetupPreflight struct {
	Checks           []SetupCheck `json:"checks"`
	RuntimeConnected bool         `json:"runtime_connected"`
	RoutingReady     bool         `json:"routing_ready"`
	// A connection check never grants permission to activate a network profile.
	AutomaticInstallAvailable bool `json:"automatic_install_available"`
}

func validateRouterSetup(in RouterSetupInput) error {
	u, e := url.Parse(in.BaseURL)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "/rest" {
		return errors.New("router_setup_https_required")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.Is4() || !ip.IsPrivate() {
		return errors.New("router_setup_private_ip_required")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || p != strconv.Itoa(n) {
			return errors.New("router_setup_invalid_port")
		}
	}
	if len(in.Username) < 1 || len(in.Username) > 128 || strings.ContainsAny(in.Username, "\x00\r\n:") || len(in.Password) < 1 || len(in.Password) > 1024 || strings.ContainsAny(in.Password, "\x00\r\n") {
		return errors.New("router_setup_credentials_required")
	}
	if len(in.CertificatePEM) > 16384 {
		return errors.New("router_setup_invalid_certificate")
	}
	if in.CertificatePEM != "" {
		rest := []byte(in.CertificatePEM)
		count := 0
		for len(strings.TrimSpace(string(rest))) > 0 {
			block, tail := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.New("router_setup_invalid_certificate")
			}
			if _, e := x509.ParseCertificate(block.Bytes); e != nil {
				return errors.New("router_setup_invalid_certificate")
			}
			rest = tail
			count++
		}
		if count == 0 {
			return errors.New("router_setup_invalid_certificate")
		}
	}
	return nil
}
func routerSetupClient(in RouterSetupInput) (RouterClient, error) {
	if e := validateRouterSetup(in); e != nil {
		return nil, e
	}
	return routeros.NewClient(in.BaseURL, in.Username, in.Password, routerSetupHTTPClient(in))
}
func routerSetupHTTPClient(in RouterSetupInput) *http.Client {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if in.CertificatePEM != "" {
		roots.AppendCertsFromPEM([]byte(in.CertificatePEM))
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func certificateFingerprint(value string) string {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}
func (s *Server) setupStatus() RouterSetupStatus {
	v := RouterSetupStatus{Configured: s.opts.Router != nil, Editable: s.opts.Runtime == nil, NativeConnected: s.opts.Runtime != nil, BaseURL: s.opts.DefaultRouterURL}
	if s.routerSetup != nil {
		v.BaseURL = s.routerSetup.BaseURL
		v.Username = s.routerSetup.Username
		v.HasPassword = true
		v.CertificateSHA256 = certificateFingerprint(s.routerSetup.CertificatePEM)
	}
	return v
}
func (s *Server) loadRouterSetup() error {
	raw, e := privateRead(filepath.Join(s.dir, "router-connection.json"), 32768)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return errors.New("protected RouterOS connection unavailable")
	}
	var in RouterSetupInput
	if decode(raw, &in) != nil || validateRouterSetup(in) != nil {
		return errors.New("invalid protected RouterOS connection")
	}
	// A running immutable native owner always retains its operator-selected client.
	if s.opts.Runtime != nil {
		return nil
	}
	client, e := routerSetupClient(in)
	if e != nil {
		return errors.New("invalid protected RouterOS connection")
	}
	s.routerSetup = &in
	s.opts.Router = &RouterResources{Client: client, Instance: s.opts.Model.Instance}
	return nil
}
func (s *Server) setupGet(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/setup/router":
		reply(w, 200, s.setupStatus())
		return true
	case "/api/v1/setup/preflight":
		p := SetupPreflight{Checks: []SetupCheck{}, RuntimeConnected: s.opts.Runtime != nil, RoutingReady: s.view().Ready}
		p.Checks = append(p.Checks, SetupCheck{"router_connection", s.opts.Router != nil, "Подключите RouterOS по HTTPS и проверьте права чтения."})
		if s.opts.Router != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			caps, e := s.opts.Router.Client.Capabilities(ctx)
			if e == nil {
				p.Checks = append(p.Checks, SetupCheck{"qualified_platform", caps.VersionSupported, "Эталонная проверенная связка — CHR x86_64 7.24.5. Для другой платформы нужно отдельно проверить установочный профиль и путь трафика."})
			} else {
				p.Checks[0].Passed = false
				p.Checks[0].Message = "Сохранённое подключение не прошло повторную проверку. Вернитесь к форме подключения."
				p.Checks = append(p.Checks, SetupCheck{"qualified_platform", false, "Не удалось повторно прочитать возможности RouterOS."})
			}
		}
		tun, te := os.Stat("/dev/net/tun")
		tunPresent := te == nil && tun.Mode()&os.ModeCharDevice != 0
		capRaw, ce := os.ReadFile("/proc/self/status")
		netAdmin := false
		if ce == nil {
			for _, line := range strings.Split(string(capRaw), "\n") {
				if strings.HasPrefix(line, "CapEff:") {
					words := strings.Fields(line)
					if len(words) == 2 {
						mask, err := strconv.ParseUint(words[1], 16, 64)
						netAdmin = err == nil && mask&(1<<12) != 0
					}
				}
			}
		}
		p.Checks = append(p.Checks, SetupCheck{"tun_device", tunPresent, "Для приёма трафика контейнеру нужно устройство /dev/net/tun."}, SetupCheck{"network_permissions", netAdmin, "Для настройки собственного сетевого пространства контейнеру нужно право NET_ADMIN."})
		p.Checks = append(p.Checks, SetupCheck{"native_profile", s.opts.Runtime != nil, "Нужен проверенный профиль маршрутизации. Сохранение доступа к RouterOS само по себе не включает перенаправление трафика."})
		p.Checks = append(p.Checks, SetupCheck{"routing_ready", p.RoutingReady, "Готовность подтверждает работающий движок и проверка полного пути трафика."})
		reply(w, 200, p)
		return true
	}
	return false
}
func setupErrorCode(err error) string {
	text := err.Error()
	if strings.HasPrefix(text, "router_setup_") {
		return text
	}
	if strings.Contains(text, "TLS verification") {
		return "router_setup_tls_untrusted"
	}
	if strings.Contains(text, "HTTP 401") {
		return "router_setup_auth_failed"
	}
	if strings.Contains(text, "HTTP 403") {
		return "router_setup_permissions_denied"
	}
	return "router_setup_unreachable"
}
func (s *Server) setupPost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/setup/router/test" && r.URL.Path != "/api/v1/setup/router/save" {
		return false
	}
	if s.opts.Runtime != nil {
		reject(w, 409, "router_setup_native_managed")
		return true
	}
	var in RouterSetupInput
	if decode(raw, &in) != nil {
		reject(w, 400, "invalid_request")
		return true
	}
	// Reuse secrets only for the identical endpoint/account. A new destination must
	// never receive credentials that the browser has not explicitly supplied.
	if old := s.routerSetup; old != nil && old.BaseURL == in.BaseURL && old.Username == in.Username {
		if in.Password == "" {
			in.Password = old.Password
		}
		if in.CertificatePEM == "" {
			in.CertificatePEM = old.CertificatePEM
		}
	}
	if e := validateRouterSetup(in); e != nil {
		reject(w, 400, e.Error())
		return true
	}
	var client RouterClient
	var e error
	if s.opts.SetupProbe != nil {
		client, e = s.opts.SetupProbe(r.Context(), in)
	} else {
		client, e = routerSetupClient(in)
	}
	if e != nil {
		reject(w, 422, setupErrorCode(e))
		return true
	}
	saved := false
	defer func() {
		if !saved {
			if closer, ok := client.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resource := &RouterResources{Client: client, Instance: s.opts.Model.Instance}
	snapshot, e := resource.Snapshot(ctx)
	if e != nil {
		reject(w, 422, setupErrorCode(e))
		return true
	}
	networkClient, ok := client.(RouterNetworkClient)
	if !ok {
		reject(w, 422, "router_setup_network_unavailable")
		return true
	}
	network, e := networkClient.Network(ctx)
	if e != nil {
		reject(w, 422, setupErrorCode(e))
		return true
	}
	result := RouterSetupResult{Status: s.setupStatus(), Router: snapshot, Network: network}
	if r.URL.Path == "/api/v1/setup/router/save" {
		// Persist before switching the active read-only client; failure retains it.
		data, e := json.Marshal(in)
		if e != nil || config.WriteAtomic(filepath.Join(s.dir, "router-connection.json"), data) != nil {
			reject(w, 503, "router_setup_save_failed")
			return true
		}
		if old := s.opts.Router; old != nil {
			if closer, ok := old.Client.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
		saved = true
		s.routerSetup = &in
		s.opts.Router = resource
		result.Saved = true
		result.Status = s.setupStatus()
		s.event("router_connection_saved", id)
	}
	reply(w, 200, result)
	return true
}
