package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
)

func privateFixture(t *testing.T) string {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	ep, e := endpoints.ParseURI("trojan://fixture-private-password@example.com:443#test")
	if e != nil {
		t.Fatal(e)
	}
	m := coreconfig.Model{SchemaVersion: 2, Instance: "probe-fixture", Mode: "socksify", Endpoints: []endpoints.Endpoint{ep}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/cache.db"}}
	b, _ := json.Marshal(map[string]any{"version": 1, "model": m})
	p := filepath.Join(dir, "draft.json")
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPrivateDraftBoundary(t *testing.T) {
	path := privateFixture(t)
	m, e := readDraft(path)
	if e != nil || len(m.Endpoints) != 1 {
		t.Fatal("valid draft rejected", e)
	}
	alias := filepath.Join(filepath.Dir(path), "alias")
	if e = os.Symlink(path, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = readDraft(alias); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(path, 0644)
	if _, e = readDraft(path); e == nil {
		t.Fatal("public credentials accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte(`{"version":1,"model":{"password":"never-print-this-private-input"}}`), 0600)
	if _, e = readDraft(path); e == nil || strings.Contains(e.Error(), "never-print") {
		t.Fatal("malformed private input was accepted or disclosed", e)
	}
}
func TestProbeRejectsCredentialBearingOrCleartextCanary(t *testing.T) {
	for _, target := range []string{"http://example.com/", "https://user:private-password@example.com/", "https://example.com/?token=private-password", "https://example.com/#private-password"} {
		var out bytes.Buffer
		e := run(context.Background(), []string{"-draft", privateFixture(t), "-state", filepath.Join(t.TempDir(), "probes"), "-url", target}, &out)
		if e == nil || strings.Contains(e.Error(), "private-password") || out.Len() != 0 {
			t.Fatal("unsafe canary accepted or disclosed", e)
		}
	}
}

func TestUnknownNodeDoesNotCreateProbeStateOrDiscloseInput(t *testing.T) {
	path := privateFixture(t)
	state := filepath.Join(filepath.Dir(path), "not-created")
	e := run(context.Background(), []string{"-draft", path, "-state", state, "-node", "private-nonexistent-id"}, &bytes.Buffer{})
	if e == nil || strings.Contains(e.Error(), "private-nonexistent") {
		t.Fatal("unknown node accepted or echoed", e)
	}
	if _, e = os.Stat(state); !os.IsNotExist(e) {
		t.Fatal("unknown node created a probe directory")
	}
}
