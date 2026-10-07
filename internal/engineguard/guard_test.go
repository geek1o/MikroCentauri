package engineguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/bounded.json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func policy() Config { return Config{Selected: []string{"selected.test", "second.test", "third.test"}} }
func TestBoundedConfiguration(t *testing.T) {
	if e := Validate(fixture(t), policy()); e != nil {
		t.Fatal(e)
	}
}
func TestAllocationEscapesRejected(t *testing.T) {
	tests := []struct {
		name   string
		modify func(map[string]any)
	}{
		{"wildcard", func(m map[string]any) { rules(m)[1].(map[string]any)["domain_suffix"] = []any{"test"} }},
		{"defaultFakeIP", func(m map[string]any) { m["dns"].(map[string]any)["final"] = "fakeip" }},
		{"extraAllocationRule", func(m map[string]any) {
			d := m["dns"].(map[string]any)
			d["rules"] = append(rules(m), map[string]any{"action": "route", "server": "fakeip"})
		}},
		{"unknownCondition", func(m map[string]any) { rules(m)[1].(map[string]any)["invert"] = true }},
		{"extraDomain", func(m map[string]any) {
			rules(m)[1].(map[string]any)["domain"] = []any{"selected.test", "second.test", "third.test", "fourth.test"}
		}},
		{"uppercaseDomain", func(m map[string]any) {
			rules(m)[1].(map[string]any)["domain"] = []any{"Selected.test", "second.test", "third.test"}
		}},
		{"AAAAAllocation", func(m map[string]any) { rules(m)[1].(map[string]any)["query_type"] = []any{"A", "AAAA"} }},
		{"synthesizedAddress", func(m map[string]any) {
			rules(m)[0].(map[string]any)["answer"] = []any{"selected.test. 30 IN A 198.18.0.2"}
		}},
		{"ipv6Pool", func(m map[string]any) {
			m["dns"].(map[string]any)["servers"].([]any)[1].(map[string]any)["inet6_range"] = "fc00::/18"
		}},
		{"bootstrapFakeIP", func(m map[string]any) {
			m["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server"] = "198.18.0.2"
		}},
		{"cacheDisabled", func(m map[string]any) { cache(m)["enabled"] = false }},
		{"cacheIDChange", func(m map[string]any) { cache(m)["cache_id"] = "other" }},
		{"cachePathChange", func(m map[string]any) { cache(m)["path"] = "/tmp/cache.db" }},
		{"cacheResetAPI", func(m map[string]any) {
			m["experimental"].(map[string]any)["clash_api"] = map[string]any{"external_controller": "127.0.0.1:9090"}
		}},
		{"exposedDNS", func(m map[string]any) { m["inbounds"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0" }},
		{"exposedSOCKS", func(m map[string]any) { m["inbounds"].([]any)[1].(map[string]any)["listen"] = "0.0.0.0" }},
		{"extraInbound", func(m map[string]any) {
			m["inbounds"] = append(m["inbounds"].([]any), map[string]any{"type": "direct", "tag": "other", "listen_port": 53})
		}},
		{"broadHijack", func(m map[string]any) {
			r := m["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			delete(r, "inbound")
			r["protocol"] = "dns"
		}},
		{"sniffBeforeBinding", func(m map[string]any) {
			r := m["route"].(map[string]any)["rules"].([]any)
			r[3], r[4] = r[4], r[3]
		}},
		{"bindingBeforeSourceOverride", func(m map[string]any) {
			r := m["route"].(map[string]any)["rules"].([]any)
			r[1], r[3] = r[3], r[1]
		}},
		{"bindingChangedToCIDR", func(m map[string]any) {
			r := m["route"].(map[string]any)["rules"].([]any)[3].(map[string]any)
			delete(r, "domain")
			r["ip_cidr"] = []any{"198.18.0.0/15"}
		}},
		{"bindingNamespaceEscape", func(m map[string]any) {
			m["route"].(map[string]any)["rules"].([]any)[3].(map[string]any)["domain"] = []any{"fourth.test"}
		}},
		{"sniffDestinationOverride", func(m map[string]any) {
			m["route"].(map[string]any)["rules"].([]any)[4].(map[string]any)["override_destination"] = true
		}},
		{"resolveAction", func(m map[string]any) {
			r := m["route"].(map[string]any)
			r["rules"] = append(r["rules"].([]any), map[string]any{"action": "resolve", "server": "fakeip"})
		}},
		{"outboundFakeIP", func(m map[string]any) { m["outbounds"].([]any)[0].(map[string]any)["domain_resolver"] = "fakeip" }},
		{"defaultResolverFakeIP", func(m map[string]any) { m["route"].(map[string]any)["default_domain_resolver"] = "fakeip" }},
		{"ruleSet", func(m map[string]any) { m["route"].(map[string]any)["rule_set"] = []any{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			if e := json.Unmarshal(fixture(t), &m); e != nil {
				t.Fatal(e)
			}
			tt.modify(m)
			b, e := json.Marshal(m)
			if e != nil {
				t.Fatal(e)
			}
			if e = Validate(b, policy()); e == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func rules(m map[string]any) []any { return m["dns"].(map[string]any)["rules"].([]any) }
func cache(m map[string]any) map[string]any {
	return m["experimental"].(map[string]any)["cache_file"].(map[string]any)
}
func TestMalformedConfiguration(t *testing.T) {
	b := fixture(t)
	for _, bad := range []string{string(b) + "{}", strings.Replace(string(b), `"final": "bootstrap"`, `"final": "fakeip", "final": "bootstrap"`, 1), "null", strings.Repeat("[", 40) + strings.Repeat("]", 40)} {
		if e := Validate([]byte(bad), policy()); e == nil {
			t.Fatal("malformed input accepted")
		}
	}
	for _, s := range [][]string{nil, {"selected.test", "selected.test"}, {"Selected.test"}, {"selected.test."}, {"*.test"}} {
		if e := Validate(b, Config{Selected: s}); e == nil {
			t.Fatalf("bad selected namespace accepted: %v", s)
		}
	}
}
func TestCachePreflight(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "engine.db")
	if e := CheckCache(p, false); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(p, true); e == nil {
		t.Fatal("lost existing cache accepted")
	}
	if e := os.WriteFile(p, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(p, false); e == nil {
		t.Fatal("empty cache accepted")
	}
	if e := os.WriteFile(p, []byte("nonempty"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(p, true); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(p, true); e == nil {
		t.Fatal("public cache accepted")
	}
	if e := os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link.db")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(link, true); e == nil {
		t.Fatal("symlink cache accepted")
	}
	parentLink := filepath.Join(dir, "parent")
	if e := os.Symlink(dir, parentLink); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(filepath.Join(parentLink, "engine.db"), true); e == nil {
		t.Fatal("symlink parent accepted")
	}
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if e := CheckCache(p, true); e == nil {
		t.Fatal("public parent accepted")
	}
}
