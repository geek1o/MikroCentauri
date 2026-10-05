package rulesets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type Policy struct {
	AllowedCIDRs []netip.Prefix
	Timeout      time.Duration
	RootCAs      *x509.CertPool
}

func (m *Manager) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range m.policy.AllowedCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func (m *Manager) download(ctx context.Context, raw string) ([]byte, error) {
	u, err := validURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.policy.Timeout)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: m.policy.RootCAs}, Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: m.policy.Timeout, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid destination")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("destination unavailable")
		}
		for _, ip := range ips {
			if !m.allowed(ip) {
				return nil, errors.New("destination refused")
			}
		}
		var conn net.Conn
		for _, ip := range ips {
			conn, err = (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("destination unavailable")
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("redirect limit")
		}
		_, err := validURL(req.URL.String())
		if err != nil {
			return err
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("TLS downgrade refused")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("rule-set request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("rule-set HTTP failure")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(MaxBytes)+1))
	if err != nil || int64(len(b)) > int64(MaxBytes) {
		return nil, errors.New("rule-set body invalid")
	}
	return b, nil
}
