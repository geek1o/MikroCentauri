package coreactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/rulesets"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAPIModelValidationDoesNotReserveOrReplaceChild(t *testing.T) {
	o, store, ledger, _ := transitionFixture(t)
	c, e := NewTransition(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	if _, e = c.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	before := c.Status()
	bindings := ledger.Mappings()
	model, e := c.CurrentModel()
	if e != nil {
		t.Fatal(e)
	}
	model.DNS.SelectedDomains = []string{"selected.test", "added.test"}
	if e = c.ValidateModel(context.Background(), before.Namespace.Revision, model); e != nil {
		t.Fatal(e)
	}
	after := c.Status()
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(bindings, ledger.Mappings()) {
		t.Fatal("API preview changed active state")
	}
	actual, _ := store.Snapshot()
	if actual.Pending != nil {
		t.Fatal("preview reserved namespace")
	}
	if e = c.ValidateModel(context.Background(), before.Namespace.Revision-1, model); e == nil || c.Status().Process.PID != before.Process.PID {
		t.Fatal("stale preview disturbed child")
	}
	current, e := c.CurrentModel()
	if e != nil || reflect.DeepEqual(current.DNS.SelectedDomains, model.DNS.SelectedDomains) {
		t.Fatal("mutable model view")
	}
}

func TestReviewedRuleSetChangeRefusesBeforeQuarantineAndResolvesOnce(t *testing.T) {
	o, store, _, _ := transitionFixture(t)
	directory := privateDir(t)
	artifact := func(payload string) rulesets.Artifact {
		data := []byte("SRS\x01" + payload)
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		path := filepath.Join(directory, hash+".srs")
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		return rulesets.Artifact{ID: "reviewed-policy", Path: path, SHA256: hash}
	}
	first, second := artifact("first"), artifact("second")
	latest := first
	calls := 0
	changeAfterRead := false
	m := o.Model
	m.RuleSets = []rulesets.Spec{{ID: "reviewed-policy", Format: "source"}}
	m.Rules = []coreconfig.Rule{{ID: "reviewed-direct", RuleSets: []string{"reviewed-policy"}, Outbound: "direct"}}
	o.Model = m
	o.ResolveRuleSets = func(context.Context, coreconfig.Model) ([]rulesets.Artifact, error) {
		calls++
		resolved := latest
		if changeAfterRead {
			latest = second
		}
		return []rulesets.Artifact{resolved}, nil
	}
	c, e := NewTransition(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	if _, e = c.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	before := c.Status()
	fp, e := c.CandidateFingerprint(context.Background(), before.Namespace.Revision, m)
	if e != nil {
		t.Fatal(e)
	}
	latest = second
	if _, e = c.ApplyPrepared(context.Background(), before.Namespace.Revision, m.DNS.SelectedDomains, m, fp); !errors.Is(e, ErrCandidateChanged) {
		t.Fatal("changed artifact applied", e)
	}
	if !reflect.DeepEqual(before, c.Status()) {
		t.Fatal("changed artifact withdrew healthy child or reserved namespace")
	}
	latest = first
	changeAfterRead = true
	previousCalls := calls
	if _, e = c.ApplyPrepared(context.Background(), before.Namespace.Revision, m.DNS.SelectedDomains, m, fp); e != nil {
		t.Fatal(e)
	}
	if calls != previousCalls+1 {
		t.Fatal("resolver raced between comparison and source pinning")
	}
	snapshot, _ := store.Snapshot()
	record, e := c.readRecord(committedView(snapshot))
	if e != nil || len(record.Artifacts) != 1 || record.Artifacts[0].SHA256 != first.SHA256 {
		t.Fatal("reviewed artifact changed during apply", e)
	}
}
