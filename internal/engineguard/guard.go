// Package engineguard restricts the disposable lab allocator to a finite namespace.
// It is a preflight policy, not a sing-box cache database verifier.
package engineguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"

	"mikrocentauri.local/core/internal/fakeip"
)

const CachePath = "/data/singbox-cache.db"

type Config struct {
	Selected  []string
	CachePath string
}

// Validate accepts only the bounded DNS allocation policy used by the lab.
// General sing-box configurations deliberately need a separate policy review.
func Validate(data []byte, cfg Config) error {
	if len(data) == 0 || len(data) > 1<<20 {
		return errors.New("engine configuration size out of bounds")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := value(dec)
	if err != nil {
		return fmt.Errorf("engine configuration: %w", err)
	}
	if _, err = dec.Token(); err != io.EOF {
		return errors.New("engine configuration has trailing data")
	}
	m, ok := root.(map[string]any)
	if !ok {
		return errors.New("engine configuration must be an object")
	}
	if !keys(m, "dns", "experimental", "inbounds", "log", "outbounds", "route") {
		return errors.New("unsupported top-level engine configuration")
	}
	if cfg.CachePath == "" {
		cfg.CachePath = CachePath
	}
	if cfg.CachePath != CachePath {
		return errors.New("unsupported engine cache path")
	}
	selected, err := names(cfg.Selected)
	if err != nil {
		return err
	}
	dns, ok := m["dns"].(map[string]any)
	if !ok || !keys(dns, "final", "rules", "servers") || dns["final"] != "bootstrap" {
		return errors.New("unsupported DNS policy")
	}
	servers, ok := dns["servers"].([]any)
	if !ok || len(servers) != 2 {
		return errors.New("exactly bootstrap and fakeip DNS servers required")
	}
	seen := map[string]bool{}
	for _, v := range servers {
		s, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid DNS server")
		}
		tag, _ := s["tag"].(string)
		if seen[tag] {
			return errors.New("duplicate DNS server")
		}
		seen[tag] = true
		switch tag {
		case "fakeip":
			if !reflect.DeepEqual(s, map[string]any{"tag": "fakeip", "type": "fakeip", "inet4_range": "198.18.0.0/15"}) {
				return errors.New("unsupported fakeip server")
			}
		case "bootstrap":
			if !keys(s, "tag", "type", "server") || s["type"] != "udp" {
				return errors.New("unsupported bootstrap server")
			}
			addr, e := netip.ParseAddr(str(s["server"]))
			if e != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() || netip.MustParsePrefix("198.18.0.0/15").Contains(addr) {
				return errors.New("bootstrap must use a real IPv4 literal")
			}
		default:
			return errors.New("unexpected DNS server")
		}
	}
	if !seen["fakeip"] || !seen["bootstrap"] {
		return errors.New("missing DNS server")
	}
	rules, ok := dns["rules"].([]any)
	if !ok || len(rules) != 2 {
		return errors.New("exactly two DNS rules required")
	}
	for i, v := range rules {
		r, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid DNS rule")
		}
		raw, ok := r["domain"].([]any)
		if !ok {
			return errors.New("exact domain namespace required")
		}
		ds := make([]string, len(raw))
		for j, x := range raw {
			var valid bool
			ds[j], valid = x.(string)
			if !valid {
				return errors.New("invalid domain namespace")
			}
		}
		ns, e := names(ds)
		if e != nil || !reflect.DeepEqual(ns, selected) {
			return errors.New("engine and publication namespaces differ")
		}
		copy := make(map[string]any, len(r))
		for k, x := range r {
			copy[k] = x
		}
		delete(copy, "domain")
		expected := map[string]any{"action": "predefined", "query_type": []any{"AAAA"}, "rcode": "NOERROR"}
		if i == 1 {
			expected = map[string]any{"action": "route", "query_type": []any{"A"}, "server": "fakeip", "rewrite_ttl": json.Number("30")}
		}
		if !reflect.DeepEqual(copy, expected) {
			return errors.New("unsupported DNS allocation rule")
		}
	}
	exp, ok := m["experimental"].(map[string]any)
	if !ok || !reflect.DeepEqual(exp, map[string]any{"cache_file": map[string]any{"enabled": true, "store_fakeip": true, "path": cfg.CachePath}}) {
		return errors.New("durable sole engine cache required; API cache reset disabled")
	}
	ins, ok := m["inbounds"].([]any)
	if !ok || len(ins) != 3 {
		return errors.New("unsupported inbound set")
	}
	seen = map[string]bool{}
	for _, v := range ins {
		in, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid inbound")
		}
		tag := str(in["tag"])
		if seen[tag] {
			return errors.New("duplicate inbound tag")
		}
		seen[tag] = true
		switch tag {
		case "dns-in":
			if !reflect.DeepEqual(in, map[string]any{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": json.Number("5354")}) {
				return errors.New("DNS allocator must listen only on loopback 5354")
			}
		case "explicit-in":
			if !reflect.DeepEqual(in, map[string]any{"type": "mixed", "tag": "explicit-in", "listen": "127.0.0.1", "listen_port": json.Number("2080")}) {
				return errors.New("unsupported explicit inbound")
			}
		case "gateway-in":
			if !keys(in, "type", "tag", "address", "auto_route", "interface_name", "mtu", "stack") || in["type"] != "tun" || in["auto_route"] != false {
				return errors.New("unsupported TUN inbound")
			}
		default:
			return errors.New("unexpected inbound")
		}
	}
	if !seen["dns-in"] || !seen["explicit-in"] || !seen["gateway-in"] {
		return errors.New("missing inbound")
	}
	out, ok := m["outbounds"].([]any)
	if !ok || len(out) != 2 {
		return errors.New("unsupported outbound set")
	}
	seen = map[string]bool{}
	for _, v := range out {
		o, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid outbound")
		}
		tag := str(o["tag"])
		if seen[tag] {
			return errors.New("duplicate outbound")
		}
		seen[tag] = true
		if o["domain_resolver"] != "bootstrap" {
			return errors.New("outbound resolution must use bootstrap")
		}
		switch tag {
		case "direct":
			if !keys(o, "tag", "type", "domain_resolver") || o["type"] != "direct" {
				return errors.New("unsupported direct outbound")
			}
		case "proxy":
			if !keys(o, "tag", "type", "domain_resolver", "server", "server_port", "uuid") || o["type"] != "vless" {
				return errors.New("unsupported proxy outbound")
			}
		default:
			return errors.New("unexpected outbound")
		}
	}
	route, ok := m["route"].(map[string]any)
	if !ok || !keys(route, "rules", "default_domain_resolver", "final") || route["default_domain_resolver"] != "bootstrap" || route["final"] != "direct" {
		return errors.New("unsupported traffic route policy")
	}
	rr, ok := route["rules"].([]any)
	if !ok {
		return errors.New("invalid traffic rules")
	}
	hijacks := 0
	for _, v := range rr {
		r, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid traffic rule")
		}
		switch r["action"] {
		case "hijack-dns":
			hijacks++
			if !reflect.DeepEqual(r, map[string]any{"action": "hijack-dns", "inbound": []any{"dns-in"}}) {
				return errors.New("DNS hijack must be restricted to dns-in")
			}
		case "sniff":
			if !reflect.DeepEqual(r, map[string]any{"action": "sniff"}) {
				return errors.New("unsupported sniff rule")
			}
		case "route":
			if !keys(r, "action", "outbound", "source_ip_cidr", "domain") || (r["outbound"] != "direct" && r["outbound"] != "proxy") {
				return errors.New("unsupported traffic routing rule")
			}
			_, s := r["source_ip_cidr"]
			_, d := r["domain"]
			if s == d {
				return errors.New("traffic rule must have one known selector")
			}
		default:
			return errors.New("unsupported traffic routing action")
		}
	}
	if hijacks != 1 {
		return errors.New("exactly one internal DNS hijack required")
	}
	return nil
}

func str(v any) string { s, _ := v.(string); return s }
func keys(m map[string]any, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func names(input []string) (map[string]bool, error) {
	if len(input) == 0 || len(input) > 4096 {
		return nil, errors.New("finite nonempty selected namespace required")
	}
	result := map[string]bool{}
	for _, s := range input {
		n, e := fakeip.CanonicalDomain(s)
		if e != nil || n != s || result[n] {
			return nil, errors.New("canonical unique ASCII domains required")
		}
		result[n] = true
	}
	return result, nil
}

// value decodes JSON without permitting duplicate object keys, including in
// otherwise irrelevant fields. Stock parsers disagree on duplicate semantics.
func value(d *json.Decoder) (any, error) { return nested(d, 0) }
func nested(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON nesting limit")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, errors.New("invalid key")
			}
			if _, exists := m[s]; exists {
				return nil, errors.New("duplicate JSON key")
			}
			v, e := nested(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated object")
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := nested(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated array")
		}
		return a, nil
	}
	return nil, errors.New("unexpected JSON delimiter")
}

// CheckCache refuses missing state when any alias has already been reserved.
// It does not open, repair, remove, or create the database. The immediate parent
// must be private; every path component must be a real directory, not a symlink.
func CheckCache(path string, required bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("cache path must be canonical absolute")
	}
	parent := filepath.Dir(path)
	for dir := parent; ; dir = filepath.Dir(dir) {
		st, e := os.Lstat(dir)
		if e != nil {
			return fmt.Errorf("cache parent: %w", e)
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("cache parent is not a real directory")
		}
		if dir == parent && st.Mode().Perm() != 0700 {
			return errors.New("cache parent must have mode 0700")
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	st, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) && !required {
		return nil
	}
	if e != nil {
		return fmt.Errorf("required engine cache: %w", e)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() == 0 {
		return errors.New("engine cache must be a nonempty regular file with mode 0600")
	}
	return nil
}
