// Package coreconfig defines the v2 product core model. Generation is offline;
// it does not authorize publication of DNS aliases or activation of RouterOS.
package coreconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/wireguard"
)

type Model struct {
	WireGuard       []wireguard.Endpoint `json:"wireguard,omitempty"`
	Services        []Service            `json:"services,omitempty"`
	RuleSets        []rulesets.Spec      `json:"rule_sets,omitempty"`
	SchemaVersion   int                  `json:"schema_version"`
	Instance        string               `json:"instance"`
	Mode            string               `json:"mode"`
	Endpoints       []endpoints.Endpoint `json:"endpoints"`
	Groups          []Group              `json:"groups"`
	Rules           []Rule               `json:"rules"`
	SourceDirect    []string             `json:"source_direct,omitempty"`
	SourceProxy     []SourcePolicy       `json:"source_proxy,omitempty"`
	DefaultOutbound string               `json:"default_outbound"`
	DNS             DNS                  `json:"dns"`
}
type Group struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Members   []string `json:"members"`
	Selected  string   `json:"selected,omitempty"`
	URL       string   `json:"url,omitempty"`
	Interval  string   `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
}
type SourcePolicy struct {
	CIDRs    []string `json:"cidrs"`
	Outbound string   `json:"outbound"`
}
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Ports    []uint16 `json:"ports"`
	Networks []string `json:"networks"`
}
type Rule struct {
	Name             string   `json:"name,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	Priority         int      `json:"priority,omitempty"`
	SourceCIDRs      []string `json:"source_cidrs,omitempty"`
	Services         []string `json:"services,omitempty"`
	RuleSets         []string `json:"rule_sets,omitempty"`
	ID               string   `json:"id"`
	Domains          []string `json:"domains,omitempty"`
	Suffixes         []string `json:"suffixes,omitempty"`
	DestinationCIDRs []string `json:"destination_cidrs,omitempty"`
	Ports            []uint16 `json:"ports,omitempty"`
	Network          string   `json:"network,omitempty"`
	Outbound         string   `json:"outbound"`
}
type DNS struct {
	Bootstrap        string   `json:"bootstrap"`
	FakeIPRange      string   `json:"fakeip_range"`
	SelectedDomains  []string `json:"selected_domains,omitempty"`
	SelectedSuffixes []string `json:"selected_suffixes,omitempty"`
	CachePath        string   `json:"cache_path"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var endpointIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func Decode(b []byte) (Model, error) {
	var m Model
	if len(b) > 4<<20 {
		return m, errors.New("core configuration too large")
	}
	if err := uniqueJSON(b); err != nil {
		return m, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, errors.New("invalid core configuration JSON")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return m, errors.New("trailing core configuration JSON")
	}
	return m, m.Validate()
}
func uniqueJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var read func(int) error
	read = func(depth int) error {
		if depth > 32 {
			return errors.New("core JSON nesting exceeds limit")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate core JSON key")
				}
				seen[s] = true
				if e = read(depth + 1); e != nil {
					return e
				}
			}
		} else if delim == '[' {
			for d.More() {
				if e = read(depth + 1); e != nil {
					return e
				}
			}
		} else {
			return errors.New("invalid core JSON")
		}
		_, e = d.Token()
		return e
	}
	if read(0) != nil {
		return errors.New("invalid or duplicate core JSON")
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing core JSON")
	}
	return nil
}
func (m Model) Validate() error {
	if m.SchemaVersion != 2 || !idPattern.MatchString(m.Instance) {
		return errors.New("invalid core schema or instance")
	}
	if m.Mode != "hybrid" && m.Mode != "full" && m.Mode != "socksify" {
		return errors.New("invalid core mode")
	}
	if len(m.Endpoints)+len(m.WireGuard) == 0 || len(m.Endpoints)+len(m.WireGuard) > 1024 || len(m.Groups) > 256 || len(m.Rules) > 4096 || len(m.SourceProxy) > 4096 {
		return errors.New("core collection bounds exceeded")
	}
	p, e := netip.ParsePrefix(m.DNS.FakeIPRange)
	if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 15 || !netip.MustParsePrefix("198.18.0.0/15").Contains(p.Addr()) {
		return errors.New("invalid core FakeIP range")
	}
	a, e := netip.ParseAddr(m.DNS.Bootstrap)
	if e != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || p.Contains(a) {
		return errors.New("invalid bootstrap DNS")
	}
	if len(m.DNS.CachePath) > 4096 || strings.ContainsAny(m.DNS.CachePath, "\x00\r\n") || !filepath.IsAbs(m.DNS.CachePath) || filepath.Clean(m.DNS.CachePath) != m.DNS.CachePath || !strings.HasPrefix(m.DNS.CachePath, "/data/") {
		return errors.New("cache path must be a clean private /data path")
	}
	if len(m.DNS.SelectedSuffixes) > 0 {
		return errors.New("suffix FakeIP publication requires finite namespace admission")
	}
	if domains(m.DNS.SelectedDomains) != nil || domains(m.DNS.SelectedSuffixes) != nil {
		return errors.New("invalid DNS domains")
	}
	refs := map[string]bool{"direct": true}
	seen := map[string]bool{"direct": true}
	groups := map[string]Group{}
	enabled := 0
	for _, ep := range m.Endpoints {
		if !endpointIDPattern.MatchString(ep.ID) || seen[ep.ID] {
			return errors.New("invalid or duplicate endpoint ID")
		}
		seen[ep.ID] = true
		if e := ep.Validate(); e != nil {
			return errors.New("invalid core endpoint")
		}
		if ep.Enabled {
			enabled++
			refs[ep.ID] = true
		} else {
			refs[ep.ID] = false
		}
	}
	for _, ep := range m.WireGuard {
		if !endpointIDPattern.MatchString(ep.ID) || seen[ep.ID] || ep.Validate() != nil {
			return errors.New("invalid or duplicate WireGuard endpoint")
		}
		seen[ep.ID] = true
		refs[ep.ID] = ep.Enabled
		if ep.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return errors.New("at least one enabled endpoint is required")
	}
	for _, g := range m.Groups {
		if !idPattern.MatchString(g.ID) || seen[g.ID] {
			return errors.New("invalid or duplicate group ID")
		}
		seen[g.ID] = true
		refs[g.ID] = true
		groups[g.ID] = g
	}
	for _, g := range m.Groups {
		if g.Type != "selector" && g.Type != "urltest" && g.Type != "fallback" {
			return errors.New("invalid group type")
		}
		if len(g.Members) == 0 || len(g.Members) > 1024 {
			return errors.New("invalid group members")
		}
		members := map[string]bool{}
		for _, v := range g.Members {
			if !refs[v] || members[v] {
				return errors.New("unknown, disabled or duplicate group member")
			}
			members[v] = true
		}
		if g.Selected != "" && !members[g.Selected] {
			return errors.New("selected node is not a member")
		}
		if g.Type == "urltest" && g.Selected != "" {
			return errors.New("urltest cannot pin a selected node")
		}
		if g.Tolerance < 0 || g.Tolerance > 60000 {
			return errors.New("invalid group tolerance")
		}
		if g.Interval != "" {
			d, e := time.ParseDuration(g.Interval)
			if e != nil || d < time.Second || d > 24*time.Hour {
				return errors.New("invalid group interval")
			}
		}
		if g.URL != "" {
			u, e := url.Parse(g.URL)
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
				return errors.New("health URL must be credential-free HTTPS")
			}
		}
	}
	visiting := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] == 1 {
			return errors.New("group cycle")
		}
		if visiting[id] == 2 {
			return nil
		}
		visiting[id] = 1
		for _, member := range groups[id].Members {
			if _, ok := groups[member]; ok {
				if e := visit(member); e != nil {
					return e
				}
			}
		}
		visiting[id] = 2
		return nil
	}
	for id := range groups {
		if e := visit(id); e != nil {
			return e
		}
	}
	if !refs[m.DefaultOutbound] {
		return errors.New("unknown default outbound")
	}
	if m.Mode == "full" && m.DefaultOutbound == "direct" {
		return errors.New("full mode requires a proxy default outbound")
	}
	if cidrs(m.SourceDirect, p) != nil {
		return errors.New("invalid direct source policy")
	}
	for _, s := range m.SourceProxy {
		if len(s.CIDRs) == 0 || cidrs(s.CIDRs, p) != nil || !refs[s.Outbound] || s.Outbound == "direct" {
			return errors.New("invalid proxy source policy")
		}
	}
	if e := m.validateRuleExtensions(p); e != nil {
		return e
	}
	ruleIDs := map[string]bool{}
	for _, r := range m.Rules {
		if !idPattern.MatchString(r.ID) || ruleIDs[r.ID] || !refs[r.Outbound] {
			return errors.New("invalid rule ID or outbound")
		}
		ruleIDs[r.ID] = true
		if len(r.Domains)+len(r.Suffixes)+len(r.DestinationCIDRs)+len(r.Ports)+len(r.SourceCIDRs)+len(r.Services)+len(r.RuleSets) == 0 {
			return errors.New("rule has no match")
		}
		if domains(r.Domains) != nil || domains(r.Suffixes) != nil || cidrs(r.DestinationCIDRs, p) != nil {
			return errors.New("invalid rule domains or CIDRs")
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return errors.New("invalid rule network")
		}
		ports := map[uint16]bool{}
		for _, port := range r.Ports {
			if port == 0 || ports[port] {
				return errors.New("invalid rule ports")
			}
			ports[port] = true
		}
	}
	return nil
}
func domains(v []string) error {
	if len(v) > 4096 {
		return errors.New("domain bound")
	}
	seen := map[string]bool{}
	for _, s := range v {
		if len(s) > 253 || !domainPattern.MatchString(s) || seen[s] {
			return errors.New("invalid domain")
		}
		seen[s] = true
	}
	return nil
}
func cidrs(v []string, fake netip.Prefix) error {
	if len(v) > 4096 {
		return errors.New("prefix bound")
	}
	seen := map[string]bool{}
	for _, s := range v {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Overlaps(fake) || seen[s] {
			return errors.New("invalid IPv4 prefix")
		}
		seen[s] = true
	}
	return nil
}
