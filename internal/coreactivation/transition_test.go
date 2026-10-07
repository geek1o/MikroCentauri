package coreactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/supervisor"
)

type transitionEngine struct{}

func (transitionEngine) Alias(ctx context.Context, n string) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	switch n {
	case "selected.test":
		return netip.MustParseAddr("198.18.0.2"), nil
	case "retired.test":
		return netip.MustParseAddr("198.18.0.3"), nil
	default:
		return netip.MustParseAddr("198.18.0.4"), nil
	}
}
func transitionFixture(t *testing.T) (TransitionOptions, *namespace.Store, *ledgerFixture, *barrierFixture) {
	t.Helper()
	o, store, ledger, _, barrier := setup(t)
	o.Engine = transitionEngine{}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return TransitionOptions{Directory: privateDir(t), Store: store, Activation: o, Model: fixtureModel(t), Process: supervisor.Options{Binary: binary, Directory: privateDir(t), ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, Validator: func(context.Context, string) error { return nil }}}, store, ledger, barrier
}
func TestTransitionRetireAddReactivateKeepsBindings(t *testing.T) {
	o, store, ledger, barrier := transitionFixture(t)
	c, err := NewTransition(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if c.Status().Ready {
		t.Fatal("constructor released disk-only generation")
	}
	if _, err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Status().Ready {
		t.Fatal("recovery did not release")
	}
	old := ledger.Mappings()
	model := fixtureModel(t)
	model.DNS.SelectedDomains = []string{"selected.test", "added.test"}
	barrier.checkCommit = func() error {
		s, _ := store.Snapshot()
		if s.Pending != nil || s.Revision != 3 {
			return errors.New("release before namespace commit")
		}
		return nil
	}
	if _, err = c.Apply(context.Background(), 2, model.DNS.SelectedDomains, model); err != nil {
		t.Fatal(err)
	}
	if !c.Status().Ready || len(ledger.Mappings()) != 3 {
		t.Fatal("candidate not admitted")
	}
	for i, m := range old {
		if ledger.Mappings()[i].Fake != m.Fake {
			t.Fatal("old alias moved")
		}
	}
	s, _ := store.Snapshot()
	if s.Known[1] != "retired.test" || s.Known[2] != "added.test" {
		t.Fatal("history lost")
	}
	barrier.checkCommit = nil
	model.DNS.SelectedDomains = []string{"selected.test", "retired.test"}
	if _, err = c.Apply(context.Background(), 3, model.DNS.SelectedDomains, model); err != nil {
		t.Fatal(err)
	}
	if len(ledger.Mappings()) != 3 || !c.Status().Ready {
		t.Fatal("reactivation lost binding")
	}
	before := c.Status().Process.PID
	if _, err = c.Apply(context.Background(), 3, model.DNS.SelectedDomains, model); err == nil || c.Status().Process.PID != before {
		t.Fatal("stale request interrupted healthy process")
	}
	if err = c.Hold(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Status().Ready || c.Status().Process.Live {
		t.Fatal("Hold did not quarantine")
	}
	if _, err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestTransitionPendingAndCommittedFailureRecoverDurably(t *testing.T) {
	for _, window := range []string{"before-commit", "after-commit"} {
		t.Run(window, func(t *testing.T) {
			o, store, _, barrier := transitionFixture(t)
			c, err := NewTransition(o)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			model := fixtureModel(t)
			model.DNS.SelectedDomains = []string{"selected.test", "added.test"}
			if window == "before-commit" {
				barrier.failVerify.Store(true)
			} else {
				barrier.checkCommit = func() error { return errors.New("release crash window") }
			}
			if _, err = c.Apply(context.Background(), 2, model.DNS.SelectedDomains, model); err == nil {
				t.Fatal("fault accepted")
			}
			actual, _ := store.Snapshot()
			if (actual.Pending != nil) != (window == "before-commit") {
				t.Fatalf("wrong durable window %+v", actual)
			}
			if c.Status().Ready || c.Status().Process.Live {
				t.Fatal("failure left runtime open")
			}
			cache := c.currentAdapter().CachePath()
			if err = c.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			barrier.failVerify.Store(false)
			barrier.checkCommit = nil
			// Initial model is deliberately the old policy: recovery must resolve the
			// persisted candidate rather than rewrite intent from constructor arguments.
			reopened, err := NewTransition(o)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close(context.Background())
			if reopened.Status().Ready {
				t.Fatal("reopened runtime trusted disk")
			}
			if _, err = reopened.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !reopened.Status().Ready || reopened.Status().Namespace.Revision != 3 || reopened.currentAdapter().CachePath() != cache {
				t.Fatal("durable recovery did not preserve namespace/cache")
			}
		})
	}
}
func TestTransitionDeniesPrivateModelTamperingAndCommitBypass(t *testing.T) {
	o, store, _, _ := transitionFixture(t)
	c, err := NewTransition(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	s, _ := store.Snapshot()
	if _, err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	desired, _ := store.Preview(2, []string{"selected.test", "added.test"})
	pending := namespace.Snapshot{Revision: desired.Pending.Revision, Known: desired.Pending.Known, Active: desired.Pending.Active}
	if c.Release(context.Background(), pending) == nil {
		t.Fatal("release bypassed namespace commit")
	}
	if err = os.Chmod(c.recordPath(s), 0644); err != nil {
		t.Fatal(err)
	}
	before := c.Status().Process.PID
	if _, err = c.Apply(context.Background(), 2, []string{"selected.test"}, fixtureModel(t)); err == nil || c.Status().Process.PID != before {
		t.Fatal("unsafe committed source accepted or interrupted engine")
	}
	os.Chmod(c.recordPath(s), 0600)
	if _, err = NewTransition(o); err == nil {
		t.Fatal("second writer accepted")
	}
	info, err := os.Stat(filepath.Join(o.Directory, "engine-cache.db"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("shared cache privacy")
	}
}

func TestTransitionBinaryRejectPreservesHealthyChildAndBoundsRetention(t *testing.T) {
	o, _, _, _ := transitionFixture(t)
	reject := false
	o.Process.Validator = func(context.Context, string) error {
		if reject {
			return errors.New("stock check failure")
		}
		return nil
	}
	c, err := NewTransition(o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := c.Status().Process.PID
	reject = true
	if _, err = c.Apply(context.Background(), 2, []string{"selected.test"}, fixtureModel(t)); err == nil || c.Status().Process.PID != before || !c.Status().Ready {
		t.Fatal("binary reject interrupted healthy generation")
	}
	reject = false
	for revision := uint64(2); revision < 11; revision++ {
		if _, err = c.Apply(context.Background(), revision, []string{"selected.test"}, fixtureModel(t)); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(o.Directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".snapshot-model.json") {
			count++
		}
	}
	if count > 7 {
		t.Fatalf("source retention unbounded: %d", count)
	}
	snapshots, err := os.ReadDir(filepath.Join(o.Directory, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) > count {
		t.Fatal("unreferenced snapshot registries retained")
	}
}

func TestTransitionRecoveryPinsSRSInsteadOfLatestResolver(t *testing.T) {
	o, _, _, barrier := transitionFixture(t)
	directory := privateDir(t)
	artifact := func(payload string) rulesets.Artifact {
		data := []byte("SRS\x01" + payload)
		hash := sha256.Sum256(data)
		digest := hex.EncodeToString(hash[:])
		path := filepath.Join(directory, digest+".srs")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return rulesets.Artifact{ID: "policy-list", Path: path, SHA256: digest}
	}
	first, second := artifact("fixture-first"), artifact("fixture-second")
	latest := first
	calls := 0
	model := fixtureModel(t)
	model.RuleSets = []rulesets.Spec{{ID: "policy-list", Format: "source"}}
	model.Rules = []coreconfig.Rule{{ID: "set-direct", RuleSets: []string{"policy-list"}, Outbound: "direct"}}
	o.Model = model
	o.ResolveRuleSets = func(context.Context, coreconfig.Model) ([]rulesets.Artifact, error) {
		calls++
		return []rulesets.Artifact{latest}, nil
	}
	c, err := NewTransition(o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	barrier.failVerify.Store(true)
	if _, err = c.Apply(context.Background(), 2, []string{"selected.test"}, model); err == nil {
		t.Fatal("missing verify failure")
	}
	if err = c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	barrier.failVerify.Store(false)
	latest = second
	if err = os.Remove(first.Path); err != nil {
		t.Fatal(err)
	}
	before := calls
	reopened, err := NewTransition(o)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(context.Background())
	if _, err = reopened.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != before {
		t.Fatal("recovery consulted mutable latest artifact")
	}
	s := reopened.Status().Namespace
	record, err := reopened.readRecord(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Artifacts) != 1 || record.Artifacts[0].SHA256 != first.SHA256 || filepath.Dir(record.Artifacts[0].Path) != filepath.Join(o.Directory, "artifacts") {
		t.Fatal("source artifact not durably pinned")
	}
}
