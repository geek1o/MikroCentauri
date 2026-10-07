package engineguard

import (
	"encoding/json"
	"testing"
)

func splitFixture(t *testing.T, active []string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(fixture(t), &m); err != nil {
		t.Fatal(err)
	}
	rules := m["route"].(map[string]any)["rules"].([]any)
	out := append([]any{}, rules[:3]...)
	selected := map[string]bool{}
	for _, name := range active {
		selected[name] = true
	}
	add := func(names []string, outbound string) {
		if len(names) != 0 {
			out = append(out, map[string]any{"action": "route", "domain": names, "outbound": outbound})
		}
	}
	retired := []string{}
	for _, name := range policy().Selected {
		if !selected[name] {
			retired = append(retired, name)
		}
	}
	add(active, "proxy")
	add(retired, "direct")
	out = append(out, map[string]any{"action": "sniff"})
	add(active, "proxy")
	m["route"].(map[string]any)["rules"] = out
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestActiveAndRetiredBindingPolicy(t *testing.T) {
	for _, active := range [][]string{{"second.test"}, {}} {
		cfg := policy()
		cfg.Active = active
		if err := Validate(splitFixture(t, active), cfg); err != nil {
			t.Fatal(err)
		}
	}
	cfg := policy()
	cfg.Active = []string{"second.test"}
	var m map[string]any
	if err := json.Unmarshal(splitFixture(t, cfg.Active), &m); err != nil {
		t.Fatal(err)
	}
	rules := m["route"].(map[string]any)["rules"].([]any)
	// Sniffing an active name on a retired alias must not win the terminal DIRECT.
	rules[4], rules[5] = rules[5], rules[4]
	b, _ := json.Marshal(m)
	if err := Validate(b, cfg); err == nil {
		t.Fatal("retired binding after sniff accepted")
	}
	rules[4], rules[5] = rules[5], rules[4]
	rules[4].(map[string]any)["outbound"] = "proxy"
	b, _ = json.Marshal(m)
	if err := Validate(b, cfg); err == nil {
		t.Fatal("retired binding to proxy accepted")
	}
}

func TestMalformedActiveNamespace(t *testing.T) {
	for _, active := range [][]string{{"second.test", "second.test"}, {"unknown.test"}, {"Second.test"}, {"second.test."}} {
		cfg := policy()
		cfg.Active = active
		if err := Validate(fixture(t), cfg); err == nil {
			t.Fatalf("accepted active %v", active)
		}
	}
	cfg := policy()
	cfg.Selected = append(cfg.Selected, "second.test")
	if err := Validate(fixture(t), cfg); err == nil {
		t.Fatal("duplicate known name accepted")
	}
	cfg = policy()
	cfg.Active = []string{}
	if err := Validate(fixture(t), cfg); err == nil {
		t.Fatal("all-active routing accepted for all-retired policy")
	}
}
