package proxy

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Endpoint is intentionally restricted to the first milestone, not a complete URI catalogue.
// Credentials never implement String or logging helpers.
type Endpoint struct {
	Name           string `json:"name"`
	Server         string `json:"server"`
	Port           uint16 `json:"port"`
	UUID           string `json:"uuid"`
	TLS            bool   `json:"tls"`
	SNI            string `json:"sni,omitempty"`
	RealityKey     string `json:"reality_key,omitempty"`
	RealityShortID string `json:"reality_short_id,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	Flow           string `json:"flow,omitempty"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ParseVLESS(raw string) (Endpoint, error) {
	fail := func(reason string) (Endpoint, error) {
		return Endpoint{}, fmt.Errorf("invalid VLESS endpoint: %s", reason)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "vless" || u.User == nil {
		return fail("expected vless URI with UUID")
	}
	if _, ok := u.User.Password(); ok {
		return fail("password userinfo not supported")
	}
	if !uuidPattern.MatchString(u.User.Username()) {
		return fail("UUID syntax")
	}
	host := u.Hostname()
	if host == "" || strings.ContainsAny(host, " \r\n\t") {
		return fail("server syntax")
	}
	if net.ParseIP(host) == nil && !validHostname(host) {
		return fail("server syntax")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return fail("explicit port required")
	}
	if u.Path != "" && u.Path != "/" {
		return fail("unexpected URI path")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fail("query syntax")
	}
	allowed := map[string]bool{"security": true, "sni": true, "type": true, "encryption": true, "pbk": true, "sid": true, "fp": true, "flow": true}
	for k, vals := range q {
		if !allowed[k] || len(vals) != 1 {
			return fail("unsupported or repeated option")
		}
	}
	if t := q.Get("type"); t != "" && t != "tcp" {
		return fail("prototype supports TCP transport only")
	}
	if e := q.Get("encryption"); e != "" && e != "none" {
		return fail("unsupported encryption")
	}
	sec := q.Get("security")
	if sec != "" && sec != "none" && sec != "tls" && sec != "reality" {
		return fail("unsupported security")
	}
	if q.Get("flow") != "" && q.Get("flow") != "xtls-rprx-vision" {
		return fail("unsupported flow")
	}
	if q.Get("flow") != "" && (sec == "" || sec == "none") {
		return fail("flow requires TLS")
	}
	if sec == "reality" && (q.Get("pbk") == "" || q.Get("fp") == "") {
		return fail("Reality requires public key and fingerprint")
	}
	if sec != "reality" && (q.Has("pbk") || q.Has("sid")) {
		return fail("Reality options require Reality security")
	}
	if q.Get("sni") != "" && !validHostname(q.Get("sni")) {
		return fail("SNI syntax")
	}
	if sec == "none" || sec == "" {
		if q.Has("sni") || q.Has("fp") {
			return fail("TLS options require TLS")
		}
	}
	name := u.Fragment
	if name == "" {
		name = host
	}
	return Endpoint{Name: name, Server: host, Port: uint16(port), UUID: strings.ToLower(u.User.Username()), TLS: sec == "tls" || sec == "reality", SNI: q.Get("sni"), RealityKey: q.Get("pbk"), RealityShortID: q.Get("sid"), Fingerprint: q.Get("fp"), Flow: q.Get("flow")}, nil
}
func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	s = strings.TrimSuffix(s, ".")
	for _, v := range strings.Split(s, ".") {
		if len(v) == 0 || len(v) > 63 || v[0] == '-' || v[len(v)-1] == '-' {
			return false
		}
		for _, c := range v {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
