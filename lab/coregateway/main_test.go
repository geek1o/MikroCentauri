package main

import (
	"os"
	"path/filepath"
	"testing"

	"mikrocentauri.local/core/internal/coreconfig"
)

func TestAllRetiredKeepsIndependentCanary(t *testing.T) {
	m, e := model(nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.DNS.SelectedDomains) != 0 || len(m.Rules) != 1 || m.Rules[0].DestinationCIDRs[0] != "10.77.0.10/32" {
		t.Fatal("canary must be independent of namespace membership")
	}
	if _, e = coreconfig.Generate(m); e != nil {
		t.Fatal(e)
	}
	m, e = model([]string{"second.test", "selected.test"})
	if e != nil {
		t.Fatal(e)
	}
	if m.DNS.SelectedDomains[0] != "second.test" {
		t.Fatal("namespace order changed")
	}
}
func TestFaultMarkerPrivateAndStrict(t *testing.T) {
	b := &faultBarrier{path: filepath.Join(t.TempDir(), "fault")}
	if b.arm("unknown") == nil {
		t.Fatal("unknown fault accepted")
	}
	if e := b.arm("after-verify"); e != nil {
		t.Fatal(e)
	}
	f, e := os.Stat(b.path)
	if e != nil {
		t.Fatal(e)
	}
	if f.Mode().Perm() != 0600 {
		t.Fatal("fault is not private")
	}
	data, _ := os.ReadFile(b.path)
	if string(data) != "after-verify" {
		t.Fatal("wrong fault persisted")
	}
	// Unrelated lifecycle calls must not consume an armed crash window.
	b.fire("before-release", 78)
	if _, e = os.Stat(b.path); e != nil {
		t.Fatal("unrelated fault consumed")
	}
}
