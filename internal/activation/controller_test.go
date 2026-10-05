package activation

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"mikrocentauri.local/core/internal/namespace"
)

type fixture struct {
	store  *namespace.Store
	events []string
	fail   string
	open   bool
	cancel context.CancelFunc
	mutate bool
}

func (f *fixture) step(ctx context.Context, name string) error {
	f.events = append(f.events, name)
	if name == "quarantine" {
		f.open = false
	}
	if name == f.fail {
		return errors.New("injected " + name)
	}
	return ctx.Err()
}
func (f *fixture) Validate(ctx context.Context, s namespace.Snapshot) error {
	return f.step(ctx, "validate")
}
func (f *fixture) Quarantine(ctx context.Context) error { return f.step(ctx, "quarantine") }
func (f *fixture) Stage(ctx context.Context, s namespace.Snapshot) error {
	if f.mutate {
		s.Known[0] = "corrupted.test"
		s.Active[0] = "corrupted.test"
	}
	return f.step(ctx, "stage")
}
func (f *fixture) Verify(ctx context.Context, s namespace.Snapshot) error {
	if s.Known[0] != "selected.test" {
		return errors.New("snapshot leaked")
	}
	if f.cancel != nil && f.fail == "cancel-verify" {
		f.cancel()
	}
	return f.step(ctx, "verify")
}
func (f *fixture) Release(ctx context.Context, s namespace.Snapshot) error {
	disk, err := f.store.Snapshot()
	if err != nil || disk.Pending != nil || disk.Revision != s.Revision {
		return errors.New("release before durable commit")
	}
	f.open = true // A partially failed release must be closed again.
	if f.cancel != nil && f.fail == "cancel-release" {
		f.cancel()
	}
	return f.step(ctx, "release")
}
func setup(t *testing.T) (*Controller, *fixture, string) {
	t.Helper()
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	dir := base + "/policy"
	s, e := namespace.New(namespace.Config{Directory: dir, Initial: []string{"selected.test"}, Capacity: 4})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	f := &fixture{store: s, open: true}
	c, e := New(s, f)
	if e != nil {
		t.Fatal(e)
	}
	return c, f, dir
}
func TestApplyOrderAndIsolation(t *testing.T) {
	c, f, _ := setup(t)
	f.mutate = true
	s, e := c.Apply(context.Background(), 1, []string{"selected.test", "second.test"})
	if e != nil {
		t.Fatal(e)
	}
	if s.Revision != 2 || s.Pending != nil || !f.open {
		t.Fatal(s)
	}
	want := []string{"validate", "quarantine", "stage", "verify", "release"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatal(f.events)
	}
}
func TestRejectBeforeDisturbingRuntime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		revision uint64
		active   []string
		fail     string
	}{
		{"stale", 0, []string{"selected.test"}, ""},
		{"invalid", 1, []string{"bad name"}, ""},
		{"capacity", 1, []string{"a.test", "b.test", "c.test", "d.test", "e.test"}, ""},
		{"configuration", 1, []string{"selected.test"}, "validate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, _ := setup(t)
			f.fail = tc.fail
			if _, e := c.Apply(context.Background(), tc.revision, tc.active); e == nil {
				t.Fatal("accepted")
			}
			for _, e := range f.events {
				if e != "validate" {
					t.Fatal(f.events)
				}
			}
			s, _ := f.store.Snapshot()
			if s.Revision != 1 || s.Pending != nil || !f.open {
				t.Fatal(s)
			}
		})
	}
}
func TestFailureBoundariesAndRestartRecovery(t *testing.T) {
	for _, boundary := range []string{"quarantine", "stage", "verify", "release", "cancel-verify", "cancel-release"} {
		t.Run(boundary, func(t *testing.T) {
			c, f, dir := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.fail = boundary
			f.cancel = cancel
			if _, e := c.Apply(ctx, 1, []string{"selected.test", "second.test"}); e == nil {
				t.Fatal("injected failure accepted")
			}
			if f.open {
				t.Fatal("runtime open after failure")
			}
			s, _ := f.store.Snapshot()
			if boundary == "quarantine" {
				if s.Pending != nil {
					t.Fatal(s)
				}
			} else if boundary == "release" || boundary == "cancel-release" {
				if s.Pending != nil || s.Revision != 2 {
					t.Fatal(s)
				}
			} else if s.Pending == nil || s.Pending.Revision != 2 {
				t.Fatal(s)
			}
			if e := f.store.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := namespace.New(namespace.Config{Directory: dir, Capacity: 4})
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			f = &fixture{store: reopened}
			c, e = New(reopened, f)
			if e != nil {
				t.Fatal(e)
			}
			s, e = c.Recover(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if s.Pending != nil || !f.open {
				t.Fatal(s)
			}
			if !reflect.DeepEqual(f.events, []string{"quarantine", "stage", "verify", "release"}) {
				t.Fatal(f.events)
			}
			if boundary != "quarantine" && (s.Revision != 2 || len(s.Known) != 2) {
				t.Fatal(s)
			}
		})
	}
}
func TestPendingRejectsNewIntent(t *testing.T) {
	c, f, _ := setup(t)
	f.fail = "verify"
	c.Apply(context.Background(), 1, []string{"selected.test", "second.test"})
	f.events = nil
	f.fail = ""
	if _, e := c.Apply(context.Background(), 1, []string{"selected.test"}); e == nil {
		t.Fatal("pending replaced")
	}
	if len(f.events) != 0 {
		t.Fatal(f.events)
	}
	s, e := c.Recover(context.Background())
	if e != nil || len(s.Known) != 2 {
		t.Fatal(s, e)
	}
}
func TestCleanupFailureIsReported(t *testing.T) {
	c, f, _ := setup(t)
	f.fail = "quarantine"
	_, e := c.Recover(context.Background())
	if e == nil || len(f.events) != 2 {
		t.Fatal(e, f.events)
	}
	// Both attempts are retained rather than silently claiming fail-closed success.
	if !strings.Contains(e.Error(), "cleanup quarantine failed") {
		t.Fatal(e)
	}
}
func TestConcurrentCompareAndSwap(t *testing.T) {
	c, _, _ := setup(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := c.Apply(context.Background(), 1, []string{"selected.test", "second.test"})
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}

func TestRecoveryNeverTrustsCommittedDiskAlone(t *testing.T) {
	c, f, _ := setup(t)
	f.fail = "verify"
	if _, e := c.Recover(context.Background()); e == nil || f.open {
		t.Fatal("released without proof", e)
	}
	s, _ := f.store.Snapshot()
	if s.Revision != 1 || s.Pending != nil {
		t.Fatal(s)
	}
	f.fail = ""
	for i := 0; i < 2; i++ {
		s, e := c.Recover(context.Background())
		if e != nil || s.Revision != 1 || !f.open {
			t.Fatal(s, e)
		}
	}
}
func TestCancelledRequests(t *testing.T) {
	c, f, _ := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Apply(ctx, 1, []string{"selected.test"}); !errors.Is(e, context.Canceled) || len(f.events) != 0 || !f.open {
		t.Fatal(e, f.events)
	}
	if _, e := c.Recover(ctx); !errors.Is(e, context.Canceled) || f.open {
		t.Fatal(e, f.events)
	}
	// The cancelled startup still attempts quarantine with a fresh cleanup context.
	if !reflect.DeepEqual(f.events, []string{"quarantine", "quarantine"}) {
		t.Fatal(f.events)
	}
}
