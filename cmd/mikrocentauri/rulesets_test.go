package main

import (
	"encoding/json"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/rulesets"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleSetCLIPrivateImportAndTrustedGeneration(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY")
	}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(dir, "set.json")
	source := []byte(`{"version":5,"rules":[{"domain":["selected.example"]}]}`)
	os.WriteFile(input, source, 0644)
	state := filepath.Join(dir, "state")
	args := []string{"-file", input, "-state", state, "-sing-box", binary, "-id", "example"}
	if rulesetCommand("ruleset-import", args) == nil {
		t.Fatal("public input accepted")
	}
	os.Chmod(input, 0600)
	if e = rulesetCommand("ruleset-import", args); e != nil {
		t.Fatal(e)
	}
	if e = rulesetCommand("ruleset-load", []string{"-state", state, "-id", "example"}); e != nil {
		t.Fatal(e)
	}
	ep, e := endpoints.ParseURI("trojan://public-test-secret@example.com:443#fixture")
	if e != nil {
		t.Fatal(e)
	}
	m := coreconfig.Model{SchemaVersion: 2, Instance: "cli", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, RuleSets: []rulesets.Spec{{ID: "example", Format: "source"}}, Rules: []coreconfig.Rule{{ID: "set-rule", RuleSets: []string{"example"}, Outbound: ep.ID}}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/cli/cache.db"}}
	model := filepath.Join(dir, "model.json")
	b, _ := json.Marshal(m)
	os.WriteFile(model, b, 0600)
	out := filepath.Join(dir, "candidate.json")
	generation := []string{"-config", model, "-out", out, "-sing-box", binary}
	if coreCommand("core-generate", generation) == nil {
		t.Fatal("missing trusted store accepted")
	}
	generation = append(generation, "-ruleset-state", state)
	if e = coreCommand("core-generate", generation); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(out)
	if strings.Contains(string(before), `"type": "remote"`) {
		t.Fatal("engine remote fetch emitted")
	}
	os.WriteFile(input, []byte(`{"version":5,"rules":[{"geosite":["legacy"]}]}`), 0600)
	if rulesetCommand("ruleset-import", args) == nil {
		t.Fatal("legacy source accepted")
	}
	if e = coreCommand("core-check", generation); e != nil {
		t.Fatal("bad rule-set candidate broke generation LKG")
	}
	after, _ := os.ReadFile(out)
	if string(before) != string(after) {
		t.Fatal("check changed active candidate")
	}
	spec := filepath.Join(dir, "spec.json")
	os.WriteFile(spec, []byte(`{"id":"blocked","url":"http://127.0.0.1/private-token","format":"source"}`), 0600)
	if e = rulesetCommand("ruleset-refresh", []string{"-state", state, "-config", spec, "-sing-box", binary}); e == nil || strings.Contains(e.Error(), "private-token") {
		t.Fatal("insecure URL allowed or leaked")
	}
}
