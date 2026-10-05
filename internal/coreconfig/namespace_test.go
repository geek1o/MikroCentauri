package coreconfig

import (
	"context"
	"encoding/json"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/singbox"
	"os"
	"path/filepath"
	"testing"
)

func TestNamespaceGenerationAndStrictPreflight(t *testing.T) {
	m := fixture(t)
	s := namespace.Snapshot{Revision: 2, Known: []string{"retired.example", "selected.example"}, Active: []string{"selected.example"}}
	o := Options{DNSPort: 5353, MixedPort: 2080, CachePath: filepath.Join(t.TempDir(), "cache.db")}
	b, e := GenerateForNamespace(m, s, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateForNamespace(b, m, s, o); e != nil {
		t.Fatal(e)
	}
	var cfg object
	json.Unmarshal(b, &cfg)
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[3].(map[string]any)["outbound"] != "direct" || rules[4].(map[string]any)["outbound"] != "backup" || rules[5].(map[string]any)["action"] != "sniff" {
		t.Fatal("retired or active routes lost terminal ordering")
	}
	alloc := cfg["dns"].(map[string]any)["rules"].([]any)[1].(map[string]any)["domain"].([]any)
	if len(alloc) != 2 || alloc[0] != "retired.example" {
		t.Fatal("historical allocator namespace lost")
	}
	for _, mutate := range []func(object){func(c object) {
		c["route"].(map[string]any)["rules"].([]any)[3].(map[string]any)["outbound"] = "manual"
	}, func(c object) {
		c["dns"].(map[string]any)["rules"].([]any)[1].(map[string]any)["domain"] = []string{"selected.example"}
	}, func(c object) { c["inbounds"].([]any)[0].(map[string]any)["listen"] = "0.0.0.0" }, func(c object) {
		c["experimental"].(map[string]any)["cache_file"].(map[string]any)["store_fakeip"] = false
	}} {
		var c object
		json.Unmarshal(b, &c)
		mutate(c)
		bad, _ := json.Marshal(c)
		if ValidateForNamespace(bad, m, s, o) == nil {
			t.Fatal("namespace policy mutation accepted")
		}
	}
	if ValidateForNamespace([]byte(`{"dns":{},"dns":{}}`), m, s, o) == nil {
		t.Fatal("duplicate key accepted")
	}
	if binary := os.Getenv("SING_BOX_BINARY"); binary != "" {
		p := filepath.Join(t.TempDir(), "candidate.json")
		os.WriteFile(p, b, 0600)
		if e = singbox.Check(context.Background(), binary, p); e != nil {
			t.Fatal(e)
		}
	}
	m.DNS.SelectedDomains = nil
	s.Active = []string{}
	b, e = GenerateForNamespace(m, s, o)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateForNamespace(b, m, s, o); e != nil {
		t.Fatal(e)
	}
}
func TestNamespaceRejectsUncommittedAndLostHistory(t *testing.T) {
	m := fixture(t)
	valid := namespace.Snapshot{Revision: 1, Known: []string{"selected.example"}, Active: []string{"selected.example"}}
	o := Options{DNSPort: 5353, MixedPort: 2080}
	for _, s := range []namespace.Snapshot{{Revision: 0, Known: valid.Known, Active: valid.Active}, {Revision: 1, Known: valid.Known, Active: valid.Active, Pending: &namespace.Pending{}}, {Revision: 1, Known: []string{"Selected.example"}, Active: valid.Active}, {Revision: 1, Known: valid.Known, Active: nil}, {Revision: 1, Known: valid.Known, Active: []string{"other.example"}}, {Revision: 1, Known: []string{"selected.example", "selected.example"}, Active: valid.Active}, {Revision: 1, Known: valid.Known, Active: []string{}}} {
		if _, e := GenerateForNamespace(m, s, o); e == nil {
			t.Fatal("invalid namespace accepted")
		}
	}
	next := namespace.Snapshot{Revision: 2, Known: []string{"selected.example", "new.example"}, Active: []string{"new.example"}}
	if e := ValidateNamespaceTransition(valid, next); e != nil {
		t.Fatal(e)
	}
	next.Known = []string{"new.example"}
	if ValidateNamespaceTransition(valid, next) == nil {
		t.Fatal("previous known name dropped")
	}
	next = valid
	next.Active = []string{}
	if ValidateNamespaceTransition(valid, next) == nil {
		t.Fatal("active changed without revision")
	}
}
