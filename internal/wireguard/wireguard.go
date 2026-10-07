// Package wireguard models modern sing-box endpoints (since 1.11), never the
// removed legacy WireGuard outbound. RouterOS native installation is separate.
package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type Peer struct {
	Address             string   `json:"address,omitempty"`
	Port                uint16   `json:"port,omitempty"`
	PublicKey           string   `json:"public_key"`
	PreSharedKey        string   `json:"pre_shared_key,omitempty"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive uint16   `json:"persistent_keepalive_interval,omitempty"`
}
type Endpoint struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Address    []string `json:"address"`
	PrivateKey string   `json:"private_key"`
	ListenPort uint16   `json:"listen_port,omitempty"`
	MTU        uint16   `json:"mtu,omitempty"`
	Peers      []Peer   `json:"peers"`
}

// NativeRouterOSWireGuardAdapter is the future native implementation boundary.
// It does not authorize installing interfaces or peers through a generic REST API.
type NativeRouterOSWireGuardAdapter interface {
	Apply(context.Context, Endpoint) error
	Remove(context.Context, string) error
}

var tagPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func validKey(s string) bool {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != s {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func (e Endpoint) validateFields() error {
	bad := func() error { return errors.New("invalid WireGuard endpoint") }
	if len(e.Name) > 256 || strings.ContainsAny(e.Name, "\x00\r\n") || !validKey(e.PrivateKey) || len(e.Address) == 0 || len(e.Address) > 8 || len(e.Peers) == 0 || len(e.Peers) > 32 {
		return bad()
	}
	if e.MTU != 0 && (e.MTU < 1280 || e.MTU > 9000) {
		return bad()
	}
	addresses := map[string]bool{}
	for _, s := range e.Address {
		p, err := netip.ParsePrefix(s)
		if err != nil || s != p.String() || !p.Addr().IsPrivate() || p.Addr().Is4In6() || addresses[s] {
			return bad()
		}
		if p.Addr().Is4() {
			a := p.Masked().Addr()
			if !a.IsPrivate() || p.Bits() < 8 || netip.MustParsePrefix("172.16.0.0/12").Contains(a) && p.Bits() < 12 || netip.MustParsePrefix("192.168.0.0/16").Contains(a) && p.Bits() < 16 {
				return bad()
			}
		} else if p.Bits() < 7 {
			return bad()
		}
		addresses[s] = true
	}
	privateBytes, _ := base64.StdEncoding.DecodeString(e.PrivateKey)
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return bad()
	}
	ownPublic := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
	keys := map[string]bool{}
	type ownerPrefix struct {
		prefix netip.Prefix
		owner  int
	}
	all := []ownerPrefix{}
	for i, p := range e.Peers {
		if !validKey(p.PublicKey) || keys[p.PublicKey] || p.PublicKey == ownPublic || p.PreSharedKey != "" && !validKey(p.PreSharedKey) || len(p.AllowedIPs) == 0 || len(p.AllowedIPs) > 128 || p.PersistentKeepalive > 600 {
			return bad()
		}
		pubBytes, _ := base64.StdEncoding.DecodeString(p.PublicKey)
		pub, err := ecdh.X25519().NewPublicKey(pubBytes)
		if err != nil {
			return bad()
		}
		if _, err = private.ECDH(pub); err != nil {
			return bad()
		}
		keys[p.PublicKey] = true
		if (p.Address == "") != (p.Port == 0) {
			return bad()
		}
		if p.Address != "" && !hostname(p.Address) {
			return bad()
		}
		for _, s := range p.AllowedIPs {
			v, err := netip.ParsePrefix(s)
			if err != nil || v != v.Masked() || s != v.String() || v.Addr().Is4In6() || v.Addr().IsMulticast() {
				return bad()
			}
			for _, prev := range all {
				if prev.prefix.Overlaps(v) {
					return bad()
				}
			}
			all = append(all, ownerPrefix{v, i})
		}
	}
	return nil
}
func hostname(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
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
func (e Endpoint) StableID() (string, error) {
	if err := e.validateFields(); err != nil {
		return "", err
	}
	c := e
	c.ID = ""
	c.Name = ""
	c.Enabled = false
	if c.MTU == 0 {
		c.MTU = 1408
	}
	c.Address = append([]string(nil), e.Address...)
	sort.Strings(c.Address)
	c.Peers = append([]Peer(nil), e.Peers...)
	for i := range c.Peers {
		c.Peers[i].Address = strings.ToLower(c.Peers[i].Address)
		c.Peers[i].AllowedIPs = append([]string(nil), c.Peers[i].AllowedIPs...)
		sort.Strings(c.Peers[i].AllowedIPs)
	}
	sort.Slice(c.Peers, func(i, j int) bool { return c.Peers[i].PublicKey < c.Peers[j].PublicKey })
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func (e Endpoint) Normalize() (Endpoint, error) {
	id, err := e.StableID()
	if err != nil {
		return Endpoint{}, err
	}
	if e.ID != "" && e.ID != id {
		return Endpoint{}, errors.New("WireGuard identity mismatch")
	}
	e.ID = id
	if e.MTU == 0 {
		e.MTU = 1408
	}
	return e, nil
}
func (e Endpoint) Validate() error { _, err := e.Normalize(); return err }
func (e Endpoint) Build(tag string) (map[string]any, error) {
	e, err := e.Normalize()
	if err != nil {
		return nil, err
	}
	if !e.Enabled || !tagPattern.MatchString(tag) {
		return nil, errors.New("WireGuard endpoint disabled or tag invalid")
	}
	peers := []any{}
	for _, p := range e.Peers {
		m := map[string]any{"public_key": p.PublicKey, "allowed_ips": p.AllowedIPs}
		if p.Address != "" {
			m["address"] = p.Address
			m["port"] = p.Port
		}
		if p.PreSharedKey != "" {
			m["pre_shared_key"] = p.PreSharedKey
		}
		if p.PersistentKeepalive != 0 {
			m["persistent_keepalive_interval"] = p.PersistentKeepalive
		}
		peers = append(peers, m)
	}
	return map[string]any{"type": "wireguard", "tag": tag, "system": false, "mtu": e.MTU, "address": e.Address, "private_key": e.PrivateKey, "listen_port": e.ListenPort, "peers": peers}, nil
}

// Preview deliberately omits all key material and per-peer credentials.
type Preview struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Protocol   string   `json:"protocol"`
	Enabled    bool     `json:"enabled"`
	Address    []string `json:"address"`
	ListenPort uint16   `json:"listen_port"`
	MTU        uint16   `json:"mtu"`
	PeerCount  int      `json:"peer_count"`
}

func (e Endpoint) Preview() Preview {
	mtu := e.MTU
	if mtu == 0 {
		mtu = 1408
	}
	return Preview{e.ID, e.Name, "wireguard", e.Enabled, append([]string(nil), e.Address...), e.ListenPort, mtu, len(e.Peers)}
}
