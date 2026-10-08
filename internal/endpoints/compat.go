package endpoints

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI normalizes common share-link transport and TLS options without
// silently weakening certificate verification or guessing unsupported transports.
func ParseURI(raw string) (Endpoint, error) {
	if len(raw) > 16384 || strings.ContainsAny(raw, "\x00\r\n") {
		return failure()
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return failure()
	}
	if u.Scheme == "vmess" {
		return parseVMess(raw)
	}
	if u.Scheme == "tuic" {
		return parseTUIC(u)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return failure()
	}
	allowed := map[string]bool{"security": true, "sni": true, "type": true, "encryption": true, "pbk": true, "sid": true, "fp": true, "flow": true, "spx": true, "alpn": true, "host": true, "path": true, "serviceName": true, "headerType": true, "mode": true, "obfs": true, "obfs-password": true, "insecure": true, "allowInsecure": true, "support-x25519mlkem768": true}
	for k, v := range q {
		if !allowed[k] || len(v) != 1 {
			return failure()
		}
	}
	for _, key := range []string{"insecure", "allowInsecure"} {
		if q.Has(key) && q.Get(key) != "0" && q.Get(key) != "false" {
			return failure()
		}
		q.Del(key)
	}
	if q.Get("headerType") != "" && q.Get("headerType") != "none" {
		return failure()
	}
	q.Del("headerType")
	if len(q.Get("spx")) > 2048 || strings.ContainsAny(q.Get("spx"), "\x00\r\n") {
		return failure()
	}
	if q.Has("spx") && (u.Scheme != "vless" || q.Get("security") != "reality") {
		return failure()
	}
	q.Del("spx")
	// This share-link field advertises client capability; the pinned TLS stack
	// negotiates hybrid groups itself. It is not a certificate-verification flag.
	if q.Has("support-x25519mlkem768") {
		v := q.Get("support-x25519mlkem768")
		if u.Scheme != "vless" || (v != "true" && v != "1") {
			return failure()
		}
		q.Del("support-x25519mlkem768")
	}
	extra := Endpoint{}
	if q.Has("alpn") {
		extra.ALPN = strings.Split(q.Get("alpn"), ",")
		if len(extra.ALPN) > 8 {
			return failure()
		}
		for _, a := range extra.ALPN {
			if len(a) == 0 || len(a) > 64 || strings.ContainsAny(a, "\x00\r\n ") {
				return failure()
			}
		}
		q.Del("alpn")
	}
	transport := q.Get("type")
	switch transport {
	case "", "tcp":
		if q.Get("host") != "" || q.Get("path") != "" || q.Get("serviceName") != "" || q.Get("mode") != "" {
			return failure()
		}
	case "ws":
		if u.Scheme != "vless" && u.Scheme != "trojan" {
			return failure()
		}
		extra.Transport = "ws"
		extra.TransportPath = q.Get("path")
		extra.TransportHost = q.Get("host")
		if extra.TransportPath == "" {
			extra.TransportPath = "/"
		}
		if !strings.HasPrefix(extra.TransportPath, "/") || q.Get("serviceName") != "" || q.Get("mode") != "" {
			return failure()
		}
		q.Set("type", "tcp")
	case "grpc":
		if u.Scheme != "vless" && u.Scheme != "trojan" {
			return failure()
		}
		if q.Get("host") != "" || q.Get("path") != "" || (q.Get("mode") != "" && q.Get("mode") != "gun") {
			return failure()
		}
		extra.Transport = "grpc"
		extra.ServiceName = q.Get("serviceName")
		q.Set("type", "tcp")
	default:
		return failure()
	}
	for _, key := range []string{"host", "path", "serviceName", "mode"} {
		q.Del(key)
	}
	for _, v := range []string{extra.TransportHost, extra.TransportPath, extra.ServiceName} {
		if len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n") {
			return failure()
		}
	}
	if extra.Transport != "" && q.Get("flow") != "" {
		return failure()
	}
	if u.Scheme == "ss" {
		if extra.Transport != "" || len(extra.ALPN) > 0 {
			return failure()
		}
		q.Del("type")
	}
	if u.Scheme == "trojan" {
		extra.Fingerprint = q.Get("fp")
		q.Del("fp")
	}
	if u.Scheme == "hysteria2" || u.Scheme == "hy2" {
		if extra.Transport != "" {
			return failure()
		}
		extra.Obfs = q.Get("obfs")
		extra.ObfsPassword = q.Get("obfs-password")
		if extra.Obfs != "" && (extra.Obfs != "salamander" || extra.ObfsPassword == "") {
			return failure()
		}
		if extra.Obfs == "" && extra.ObfsPassword != "" {
			return failure()
		}
		if len(extra.ObfsPassword) > 1024 || strings.ContainsAny(extra.ObfsPassword, "\x00\r\n") {
			return failure()
		}
		q.Del("obfs")
		q.Del("obfs-password")
		q.Del("fp") // uTLS is TCP-only, not a QUIC fingerprint.
	} else if q.Has("obfs") || q.Has("obfs-password") {
		return failure()
	}
	u.RawQuery = q.Encode()
	ep, err := parseBasicURI(u.String())
	if err != nil {
		return failure()
	}
	ep.Transport, ep.TransportHost, ep.TransportPath, ep.ServiceName = extra.Transport, extra.TransportHost, extra.TransportPath, extra.ServiceName
	ep.ALPN = extra.ALPN
	ep.Obfs, ep.ObfsPassword = extra.Obfs, extra.ObfsPassword
	if extra.Fingerprint != "" {
		ep.Fingerprint = extra.Fingerprint
	}
	if (!ep.TLS && len(ep.ALPN) > 0) || !validFingerprint(ep.Fingerprint) {
		return failure()
	}
	return identify(ep)
}
func identify(e Endpoint) (Endpoint, error) {
	e.Enabled = true
	e.ID = ""
	canonical := e
	canonical.Enabled = false
	canonical.Name = ""
	b, _ := json.Marshal(canonical)
	h := sha256.Sum256(b)
	e.ID = hex.EncodeToString(h[:])
	return e, nil
}
func validFingerprint(s string) bool {
	switch s {
	case "", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized":
		return true
	}
	return false
}
func parseTUIC(u *url.URL) (Endpoint, error) {
	if u.User == nil {
		return failure()
	}
	password, ok := u.User.Password()
	if !ok || password == "" || len(password) > 1024 {
		return failure()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return failure()
	}
	for k, v := range q {
		if len(v) != 1 {
			return failure()
		}
		switch k {
		case "sni", "alpn", "congestion_control", "udp_relay_mode", "allow_insecure":
		default:
			return failure()
		}
	}
	if q.Has("allow_insecure") && q.Get("allow_insecure") != "0" && q.Get("allow_insecure") != "false" {
		return failure()
	}
	cc := q.Get("congestion_control")
	if cc != "" && cc != "cubic" && cc != "new_reno" && cc != "bbr" {
		return failure()
	}
	mode := q.Get("udp_relay_mode")
	if mode != "" && mode != "native" && mode != "quic" {
		return failure()
	}
	copy := *u
	copy.Scheme = "vless"
	copy.User = url.User(u.User.Username())
	nq := url.Values{"security": []string{"tls"}}
	for _, k := range []string{"sni", "alpn"} {
		if q.Has(k) {
			nq.Set(k, q.Get(k))
		}
	}
	copy.RawQuery = nq.Encode()
	e, err := ParseURI(copy.String())
	if err != nil {
		return failure()
	}
	e.Protocol = "tuic"
	e.Password = password
	e.CongestionControl = cc
	e.UDPRelayMode = mode
	return identify(e)
}
func parseVMess(raw string) (Endpoint, error) {
	data, err := decode64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil || len(data) > 16384 {
		return failure()
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return failure()
	}
	for k := range obj {
		switch k {
		case "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp":
		default:
			return failure()
		}
	}
	value := func(key string) string {
		var s string
		if json.Unmarshal(obj[key], &s) == nil {
			return s
		}
		var n json.Number
		if json.Unmarshal(obj[key], &n) == nil {
			return n.String()
		}
		return ""
	}
	if value("type") != "" && value("type") != "none" {
		return failure()
	}
	security := value("scy")
	if security == "" {
		security = "auto"
	}
	switch security {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
	default:
		return failure()
	}
	aid := 0
	if value("aid") != "" {
		n, e := strconv.Atoi(value("aid"))
		if e != nil || n < 0 || n > 65535 {
			return failure()
		}
		aid = n
	}
	network := value("net")
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "ws" && network != "grpc" {
		return failure()
	}
	q := url.Values{"type": []string{network}}
	if value("tls") == "tls" {
		q.Set("security", "tls")
	} else if value("tls") != "" {
		return failure()
	}
	for _, key := range []string{"sni", "alpn", "fp"} {
		if value(key) != "" {
			q.Set(key, value(key))
		}
	}
	if network == "ws" {
		q.Set("host", value("host"))
		q.Set("path", value("path"))
	} else if network == "grpc" {
		q.Set("serviceName", value("path"))
	} else if value("host") != "" || value("path") != "" {
		return failure()
	}
	u := url.URL{Scheme: "vless", User: url.User(value("id")), Host: value("add") + ":" + value("port"), RawQuery: q.Encode(), Fragment: value("ps")}
	if strings.Contains(value("add"), ":") {
		u.Host = "[" + value("add") + "]:" + value("port")
	}
	e, err := ParseURI(u.String())
	if err != nil {
		return failure()
	}
	e.Protocol = "vmess"
	e.Method = security
	e.AlterID = aid
	return identify(e)
}
func vmessURI(e Endpoint) string {
	network := e.Transport
	if network == "" {
		network = "tcp"
	}
	path := e.TransportPath
	if network == "grpc" {
		path = e.ServiceName
	}
	obj := map[string]string{"v": "2", "ps": e.Name, "add": e.Server, "port": strconv.Itoa(int(e.Port)), "id": e.UUID, "aid": strconv.Itoa(e.AlterID), "scy": e.Method, "net": network, "type": "none", "host": e.TransportHost, "path": path, "sni": e.SNI, "alpn": strings.Join(e.ALPN, ","), "fp": e.Fingerprint}
	if e.TLS {
		obj["tls"] = "tls"
	}
	b, _ := json.Marshal(obj)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}
