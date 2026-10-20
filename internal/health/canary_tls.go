package health

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// CanaryTLS preserves a literal dial destination while verifying the operator's
// DNS certificate name. It does not resolve that name or weaken TLS trust.
func CanaryTLS(target, serverName string) (*tls.Config, string, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if serverName == "" {
		return c, "", nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return nil, "", errors.New("TLS name requires a literal HTTPS canary")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Zone() != "" || (!ip.IsGlobalUnicast() && !ip.IsLoopback()) || len(serverName) > 253 || strings.HasSuffix(serverName, ".") || !strings.Contains(serverName, ".") {
		return nil, "", errors.New("invalid canary TLS name or literal destination")
	}
	if _, err := netip.ParseAddr(serverName); err == nil {
		return nil, "", errors.New("canary TLS name must be a DNS name")
	}
	for _, label := range strings.Split(serverName, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, "", errors.New("invalid canary TLS name")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return nil, "", errors.New("invalid canary TLS name")
			}
		}
	}
	c.ServerName = serverName
	host := serverName
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(serverName, port)
	}
	return c, host, nil
}
