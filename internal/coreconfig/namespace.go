package coreconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/namespace"
	"net/netip"
	"reflect"
)

// GenerateForNamespace configures the private allocator for the whole reserved
// history. Public DNS remains controlled by dnsgate: retired names receive real
// DNS there, while previously issued synthetic destinations retain DIRECT routes.
// A snapshot is only structural input; callers must obtain it from the locked
// durable namespace store and verify engine/ledger bindings before publication.
func GenerateForNamespace(m Model, s namespace.Snapshot, o Options) ([]byte, error) {
	if e := validateNamespace(s); e != nil {
		return nil, e
	}
	if len(m.DNS.SelectedDomains) != len(s.Active) {
		return nil, errors.New("model selected domains differ from active namespace")
	}
	for i, n := range s.Active {
		if m.DNS.SelectedDomains[i] != n {
			return nil, errors.New("model selected domains differ from active namespace")
		}
	}
	if m.Mode == "socksify" {
		return nil, errors.New("namespace generation requires hybrid or full ingress")
	}
	b, e := GenerateWithOptions(m, o)
	if e != nil {
		return nil, e
	}
	pool, _ := netip.ParsePrefix(m.DNS.FakeIPRange)
	if uint64(len(s.Known)) >= uint64(1)<<uint(32-pool.Bits()) {
		return nil, errors.New("namespace exceeds allocator prefix capacity")
	}
	var cfg object
	if e = json.Unmarshal(b, &cfg); e != nil {
		return nil, errors.New("generated namespace JSON failure")
	}
	dns := cfg["dns"].(map[string]any)
	dns["servers"] = []object{{"type": "udp", "tag": "bootstrap", "server": m.DNS.Bootstrap}, {"type": "fakeip", "tag": "fakeip", "inet4_range": m.DNS.FakeIPRange}}
	dns["rules"] = []object{{"domain": s.Known, "query_type": []string{"AAAA"}, "action": "predefined", "rcode": "NOERROR"}, {"domain": s.Known, "query_type": []string{"A"}, "action": "route", "server": "fakeip", "rewrite_ttl": 30}}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	prefixCount := 1 + len(m.SourceProxy)
	if len(m.SourceDirect) > 0 {
		prefixCount++
	}
	next := append([]any(nil), rules[:prefixCount]...)
	active := map[string]bool{}
	for _, n := range s.Active {
		active[n] = true
	}
	for _, n := range s.Known {
		outbound := "direct"
		if active[n] {
			outbound = m.SelectedOutbound(n)
		}
		next = append(next, object{"domain": []string{n}, "action": "route", "outbound": outbound})
	}
	next = append(next, rules[prefixCount+len(s.Active):]...)
	route["rules"] = next
	result, e := json.MarshalIndent(cfg, "", "  ")
	if e != nil || len(result) > 4<<20 {
		return nil, errors.New("generated namespace JSON exceeds bounds")
	}
	return result, nil
}

// ValidateForNamespace is a closed generator policy, not an arbitrary sing-box
// schema validator. Any candidate deviation, including missing retired names,
// new listeners, sniff reordering, extra rules or relaxed cache options, fails.
// Binary schema checking and live alias admission remain separate requirements.
func ValidateForNamespace(data []byte, m Model, s namespace.Snapshot, o Options) error {
	if len(data) == 0 || len(data) > 4<<20 {
		return errors.New("namespace engine JSON exceeds bounds")
	}
	if uniqueJSON(data) != nil {
		return errors.New("invalid namespace engine JSON")
	}
	expected, e := GenerateForNamespace(m, s, o)
	if e != nil {
		return e
	}
	decode := func(b []byte) (any, error) {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		var v any
		e := d.Decode(&v)
		return v, e
	}
	got, e := decode(data)
	if e != nil {
		return errors.New("invalid namespace engine JSON")
	}
	want, e := decode(expected)
	if e != nil {
		return errors.New("generated namespace JSON failure")
	}
	if !reflect.DeepEqual(got, want) {
		return errors.New("namespace engine differs from generated policy")
	}
	return nil
}

// ValidateNamespaceTransition enforces append-only reservation history. A model
// update within one revision must preserve Known and Active; a namespace change
// must advance exactly one committed revision without dropping prior names.
func ValidateNamespaceTransition(previous, next namespace.Snapshot) error {
	if e := validateNamespace(previous); e != nil {
		return e
	}
	if e := validateNamespace(next); e != nil {
		return e
	}
	if next.Revision == previous.Revision {
		if !reflect.DeepEqual(previous.Known, next.Known) || !reflect.DeepEqual(previous.Active, next.Active) {
			return errors.New("namespace changed without a revision")
		}
		return nil
	}
	if previous.Revision == math.MaxUint64 || next.Revision != previous.Revision+1 || len(next.Known) < len(previous.Known) || !reflect.DeepEqual(next.Known[:len(previous.Known)], previous.Known) {
		return errors.New("namespace history or revision lost")
	}
	return nil
}
func validateNamespace(s namespace.Snapshot) error {
	if s.Revision == 0 || s.Pending != nil || len(s.Known) < 1 || len(s.Known) > 4096 || s.Active == nil || len(s.Active) > len(s.Known) {
		return errors.New("committed finite namespace required")
	}
	known := map[string]bool{}
	for _, n := range s.Known {
		canonical, e := fakeip.CanonicalDomain(n)
		if e != nil || canonical != n || known[n] {
			return errors.New("invalid known namespace")
		}
		known[n] = true
	}
	active := map[string]bool{}
	for _, n := range s.Active {
		canonical, e := fakeip.CanonicalDomain(n)
		if e != nil || canonical != n || !known[n] || active[n] {
			return errors.New("invalid active namespace")
		}
		active[n] = true
	}
	return nil
}
