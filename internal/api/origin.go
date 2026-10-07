package api

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// CanonicalOrigin validates an operator-supplied HTTPS origin. It performs no
// DNS lookup and trusts no request/proxy headers. Browser default-port and host
// normalization is applied once, before exact request comparisons.
func CanonicalOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(origin, "?#@") || strings.ContainsAny(u.Host, "%*\\ \t\r\n") {
		return "", errors.New("exact HTTPS origin without credentials or path required")
	}
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsUnspecified() || ip.Is4In6() || ip.Zone() != "" {
			return "", errors.New("invalid origin IP address")
		}
		host = ip.String()
	} else {
		if len(host) == 0 || len(host) > 253 {
			return "", errors.New("invalid origin hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid origin hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", errors.New("invalid origin hostname")
				}
			}
		}
	}
	port := u.Port()
	if port == "" && strings.HasSuffix(u.Host, ":") {
		return "", errors.New("invalid origin port")
	}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", errors.New("invalid origin port")
		}
		port = strconv.Itoa(p)
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}
