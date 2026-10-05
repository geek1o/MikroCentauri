// Package endpoints imports a deliberately strict, credential-redacting URI subset.
package endpoints

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mikrocentauri.local/core/internal/proxy"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Endpoint struct {
	Enabled        bool   `json:"enabled"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	Server         string `json:"server"`
	Port           uint16 `json:"port"`
	UUID           string `json:"uuid,omitempty"`
	Password       string `json:"password,omitempty"`
	Method         string `json:"method,omitempty"`
	TLS            bool   `json:"tls"`
	SNI            string `json:"sni,omitempty"`
	RealityKey     string `json:"reality_key,omitempty"`
	RealityShortID string `json:"reality_short_id,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	Flow           string `json:"flow,omitempty"`
}

type Preview struct {
	ID, Name, Protocol, Server, Transport, SNI, Fingerprint string
	Port                                                    uint16
	TLS, Reality                                            bool
}

func (e Endpoint) Preview() Preview {
	transport := "tcp"
	if e.Protocol == "hysteria2" {
		transport = "quic"
	}
	return Preview{e.ID, e.Name, e.Protocol, e.Server, transport, e.SNI, e.Fingerprint, e.Port, e.TLS, e.RealityKey != ""}
}
func failure() (Endpoint, error) {
	return Endpoint{}, errors.New("invalid or unsupported endpoint URI")
}
func ParseURI(raw string) (Endpoint, error) {
	if len(raw) > 16384 || strings.ContainsAny(raw, "\r\n\x00") {
		return failure()
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return failure()
	}
	var e Endpoint
	if u.Scheme == "vless" {
		v, err := proxy.ParseVLESS(raw)
		if err != nil {
			return failure()
		}
		e = Endpoint{Name: v.Name, Protocol: "vless", Server: strings.ToLower(v.Server), Port: v.Port, UUID: v.UUID, TLS: v.TLS, SNI: v.SNI, RealityKey: v.RealityKey, RealityShortID: v.RealityShortID, Fingerprint: v.Fingerprint, Flow: v.Flow}
	} else {
		if u.Scheme != "ss" && u.Scheme != "trojan" && u.Scheme != "hysteria2" && u.Scheme != "hy2" {
			return failure()
		}
		if u.User == nil || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
			return failure()
		}
		host := strings.ToLower(u.Hostname())
		if !validHost(host) {
			return failure()
		}
		p, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || p == 0 {
			return failure()
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return failure()
		}
		for k, v := range q {
			if len(v) != 1 || (k != "sni" && k != "security" && k != "type") {
				return failure()
			}
		}
		e = Endpoint{Protocol: u.Scheme, Server: host, Port: uint16(p), Name: u.Fragment}
		if e.Name == "" {
			e.Name = host
		}
		if u.Scheme == "ss" {
			if len(q) != 0 {
				return failure()
			}
			auth := u.User.String()
			method, pass, ok := strings.Cut(auth, ":")
			if !ok {
				b, err := decode64(u.User.Username())
				if err != nil {
					return failure()
				}
				method, pass, ok = strings.Cut(string(b), ":")
			} else {
				method = u.User.Username()
				pass, _ = u.User.Password()
			}
			if !ok || pass == "" || !ssMethods[method] {
				return failure()
			}
			e.Method = method
			e.Password = pass
		} else {
			if _, ok := u.User.Password(); ok {
				return failure()
			}
			e.Password = u.User.Username()
			if e.Password == "" {
				return failure()
			}
			e.TLS = true
			e.SNI = q.Get("sni")
			if e.SNI != "" && !validHost(e.SNI) {
				return failure()
			}
			if q.Get("security") != "" && q.Get("security") != "tls" {
				return failure()
			}
			if q.Get("type") != "" && q.Get("type") != "tcp" {
				return failure()
			}
			if e.Protocol == "hy2" {
				e.Protocol = "hysteria2"
			}
			if e.Protocol == "hysteria2" && q.Has("type") {
				return failure()
			}
		}
	}
	if e.RealityKey != "" {
		b, err := base64.RawURLEncoding.DecodeString(e.RealityKey)
		if err != nil || len(b) != 32 {
			return failure()
		}
		if len(e.RealityShortID) > 16 || len(e.RealityShortID)%2 != 0 {
			return failure()
		}
		if _, err := hex.DecodeString(e.RealityShortID); err != nil {
			return failure()
		}
	}
	if e.Fingerprint != "" {
		switch e.Fingerprint {
		case "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized":
		default:
			return failure()
		}
	}
	if len(e.Name) > 256 || strings.ContainsAny(e.Name, "\x00\r\n") {
		return failure()
	}
	e.Enabled = true
	canonical := e
	canonical.Enabled = false
	canonical.ID = ""
	canonical.Name = ""
	b, _ := json.Marshal(canonical)
	h := sha256.Sum256(b)
	e.ID = hex.EncodeToString(h[:])
	return e, nil
}

var ssMethods = map[string]bool{"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true, "chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true}

func decode64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, e := enc.DecodeString(s); e == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, v := range strings.Split(strings.TrimSuffix(s, "."), ".") {
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
func (e Endpoint) Outbound(tag string) map[string]any {
	m := map[string]any{"type": e.Protocol, "tag": tag, "server": e.Server, "server_port": e.Port}
	if e.Protocol == "vless" {
		m["uuid"] = e.UUID
		if e.Flow != "" {
			m["flow"] = e.Flow
		}
	} else {
		m["password"] = e.Password
	}
	if e.Protocol == "ss" {
		m["type"] = "shadowsocks"
		m["method"] = e.Method
	}
	if e.TLS {
		t := map[string]any{"enabled": true}
		if e.SNI != "" {
			t["server_name"] = e.SNI
		}
		if e.Fingerprint != "" {
			t["utls"] = map[string]any{"enabled": true, "fingerprint": e.Fingerprint}
		}
		if e.RealityKey != "" {
			t["reality"] = map[string]any{"enabled": true, "public_key": e.RealityKey, "short_id": e.RealityShortID}
		}
		m["tls"] = t
	}
	return m
}

// Validate rejects structurally invalid or tampered serialized endpoints.
func (e Endpoint) Validate() error {
	if !validHost(e.Server) || e.Port == 0 || len(e.Name) > 256 || strings.ContainsAny(e.Name, "\x00\r\n") {
		return errors.New("invalid endpoint")
	}
	var raw string
	host := net.JoinHostPort(e.Server, strconv.Itoa(int(e.Port)))
	q := url.Values{}
	switch e.Protocol {
	case "vless":
		if e.TLS {
			q.Set("security", "tls")
		}
		if e.RealityKey != "" {
			q.Set("security", "reality")
			q.Set("pbk", e.RealityKey)
			if e.RealityShortID != "" {
				q.Set("sid", e.RealityShortID)
			}
		}
		if e.SNI != "" {
			q.Set("sni", e.SNI)
		}
		if e.Fingerprint != "" {
			q.Set("fp", e.Fingerprint)
		}
		if e.Flow != "" {
			q.Set("flow", e.Flow)
		}
		raw = "vless://" + url.User(e.UUID).String() + "@" + host
	case "ss":
		if e.TLS {
			return errors.New("invalid endpoint")
		}
		raw = "ss://" + url.UserPassword(e.Method, e.Password).String() + "@" + host
	case "trojan", "hysteria2":
		if !e.TLS {
			return errors.New("invalid endpoint")
		}
		if e.SNI != "" {
			q.Set("sni", e.SNI)
		}
		raw = e.Protocol + "://" + url.User(e.Password).String() + "@" + host
	default:
		return errors.New("invalid endpoint")
	}
	if len(q) > 0 {
		raw += "?" + q.Encode()
	}
	raw += "#" + url.PathEscape(e.Name)
	rebuilt, err := ParseURI(raw)
	if err != nil {
		return errors.New("invalid endpoint")
	}
	a := e
	b := rebuilt
	a.Enabled = false
	b.Enabled = false
	a.ID = ""
	b.ID = ""
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) || (e.ID != "" && e.ID != rebuilt.ID) {
		return errors.New("invalid endpoint")
	}
	return nil
}
