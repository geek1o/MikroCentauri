package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mikrocentauri.local/core/internal/proxy"
)

type Config struct {
	SchemaVersion int      `json:"schema_version"`
	Instance      string   `json:"instance"`
	Mode          string   `json:"mode"`
	VLESSURI      string   `json:"vless_uri"`
	Domains       []string `json:"domains"`
	DirectSources []string `json:"direct_sources,omitempty"`
	ProxySources  []string `json:"proxy_sources,omitempty"`
	FakeIPRange   string   `json:"fakeip_range"`
	LANInterface  string   `json:"lan_interface"`
	LANRouterIP   string   `json:"lan_router_ip"`
	GatewayIP     string   `json:"gateway_ip"`
	DNSUpstream   string   `json:"dns_upstream"`
}

var safeID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func Decode(b []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid configuration JSON")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return errors.New("unsupported schema_version")
	}
	if !safeID.MatchString(c.Instance) || !safeID.MatchString(c.LANInterface) {
		return errors.New("invalid instance or LAN interface")
	}
	if c.Mode != "hybrid" && c.Mode != "full" && c.Mode != "socksify" {
		return errors.New("invalid spike mode")
	}
	if _, err := proxy.ParseVLESS(c.VLESSURI); err != nil {
		return err
	}
	if len(c.Domains) == 0 {
		return errors.New("at least one selected domain required")
	}
	seen := map[string]bool{}
	for _, v := range c.Domains {
		if v != strings.ToLower(v) || len(v) > 253 || !domainPattern.MatchString(v) || seen[v] {
			return errors.New("invalid or duplicate domain")
		}
		seen[v] = true
	}
	p, err := netip.ParsePrefix(c.FakeIPRange)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 15 || !netip.MustParsePrefix("198.18.0.0/15").Contains(p.Addr()) {
		return errors.New("spike FakeIP range must be aligned within 198.18.0.0/15")
	}
	for _, v := range []string{c.GatewayIP, c.LANRouterIP, c.DNSUpstream} {
		a, e := netip.ParseAddr(v)
		if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || p.Contains(a) {
			return errors.New("invalid or conflicting IPv4 network address")
		}
	}
	if c.GatewayIP == c.LANRouterIP || c.GatewayIP == c.DNSUpstream {
		return errors.New("gateway conflict or DNS loop")
	}
	sources := map[string]bool{}
	for _, list := range [][]string{c.DirectSources, c.ProxySources} {
		for _, v := range list {
			q, e := netip.ParsePrefix(v)
			if e != nil || !q.Addr().Is4() || q != q.Masked() || q.Overlaps(p) {
				return errors.New("invalid or conflicting source prefix")
			}
			if sources[v] {
				return errors.New("conflicting source policies")
			}
			sources[v] = true
		}
	}
	// Router-wide collision discovery is a separate capability gate, never implied here.
	return nil
}

// WriteAtomic persists secrets with restrictive permissions and syncs both file and directory.
func WriteAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".candidate-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("commit candidate: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
