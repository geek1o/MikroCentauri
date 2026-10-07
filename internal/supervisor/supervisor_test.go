package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "run" && os.Args[2] == "-c" {
		b, err := os.ReadFile(os.Args[3])
		if err != nil {
			os.Exit(2)
		}
		if strings.Contains(string(b), `"crash"`) {
			time.Sleep(80 * time.Millisecond)
			os.Exit(3)
		}
		for {
			time.Sleep(time.Second)
		}
	}
}
func directory(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0700)
	return p
}
func options(t *testing.T) Options {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	opts := Options{Binary: exe, Directory: directory(t), StopTimeout: 50 * time.Millisecond, ReadyTimeout: time.Second, BackoffInitial: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond, CrashLimit: 3, Semantic: func(b []byte) error {
		if !json.Valid(b) {
			return errors.New("secret-semantic")
		}
		return nil
	}, Validator: func(ctx context.Context, p string) error {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), `"invalid"`) {
			return errors.New("secret-validator")
		}
		return nil
	}}
	opts.Hooks = Hooks{Quarantine: func(context.Context) error { return nil }, Prepare: func(context.Context, string) error { return nil }, Probe: func(ctx context.Context, p string) error {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), `"bad-ready"`) {
			return errors.New("secret-readiness")
		}
		time.Sleep(10 * time.Millisecond)
		return nil
	}, Release: func(context.Context) error { return nil }}
	return opts
}
func TestApplyRejectRollbackAndReopen(t *testing.T) {
	o := options(t)
	releaseCount := 0
	o.Hooks.Release = func(context.Context) error {
		releaseCount++
		b, e := os.ReadFile(filepath.Join(o.Directory, "journal.json"))
		var j journal
		if e != nil || json.Unmarshal(b, &j) != nil || j.Active == "" || j.Pending != "" || j.PID == 0 {
			t.Error("release preceded durablecommit")
		}
		return nil
	}
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Apply(context.Background(), []byte(`{"mode":"good","secret":"password"}`)); e != nil {
		t.Fatal(e)
	}
	before := s.Status()
	if !before.Live || !before.Ready || before.PID == 0 {
		t.Fatal(before)
	}
	if e = s.Apply(context.Background(), []byte(`{"mode":"invalid"}`)); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("invalid candidate or leak")
	}
	if s.Status().PID != before.PID {
		t.Fatal("validator disturbed healthy child")
	}
	if e = s.Apply(context.Background(), []byte(`{"mode":"bad-ready"}`)); e == nil {
		t.Fatal("bad readiness accepted")
	}
	after := s.Status()
	if !after.Ready || after.Revision != before.Revision || after.PID == before.PID {
		t.Fatal("LKG rollback failed", after)
	}
	if releaseCount != 2 {
		t.Fatal("release count")
	}
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	s2, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close(context.Background())
	if e = s2.Start(context.Background()); e != nil || s2.Status().Revision != before.Revision || !s2.Status().Ready {
		t.Fatal("reopen LKG", e)
	}
	for _, event := range s2.Events() {
		if strings.Contains(event.Code, "password") {
			t.Fatal("leaked")
		}
	}
}
func TestCrashLoopAndStopDuringBackoff(t *testing.T) {
	o := options(t)
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Apply(context.Background(), []byte(`{"mode":"crash"}`)); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.Status().State != "crash-loop" {
		time.Sleep(5 * time.Millisecond)
	}
	status := s.Status()
	if status.State != "crash-loop" || status.Ready || status.Live || status.Restarts != 2 {
		t.Fatal("bounded crashloop", status)
	}
	if e = s.Stop(context.Background()); e != nil {
		t.Fatal(e)
	}
	time.Sleep(100 * time.Millisecond)
	if s.Status().Live {
		t.Fatal("Stop restarted child")
	}
}
func TestLockPermissionsTamperAndRetention(t *testing.T) {
	o := options(t)
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = New(o); e == nil {
		t.Fatal("duplicate supervisor")
	}
	for i := 0; i < 7; i++ {
		data, _ := json.Marshal(map[string]any{"mode": "good", "revision": i})
		if e = s.Apply(context.Background(), data); e != nil {
			t.Fatal(e)
		}
	}
	if len(s.j.KnownGood) != 5 {
		t.Fatal("retention")
	}
	files, _ := os.ReadDir(o.Directory)
	n := 0
	for _, f := range files {
		if hashPattern.MatchString(strings.TrimSuffix(f.Name(), ".json")) {
			n++
			st, _ := os.Stat(filepath.Join(o.Directory, f.Name()))
			if st.Mode().Perm() != 0600 {
				t.Fatal("revision permissions")
			}
		}
	}
	if n != 5 {
		t.Fatal("old revisions not pruned")
	}
	active := s.j.Active
	s.Close(context.Background())
	os.WriteFile(filepath.Join(o.Directory, active+".json"), []byte(`{"tampered":true}`), 0600)
	if _, e = New(o); e == nil {
		t.Fatal("hash tamper accepted")
	}
}
func TestPendingRecoveryAndAmbiguousPID(t *testing.T) {
	o := options(t)
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	s.Apply(context.Background(), []byte(`{"mode":"good"}`))
	s.Stop(context.Background())
	data := []byte(`{"mode":"bad-ready"}`)
	sum := sha256.Sum256(data)
	pending := hex.EncodeToString(sum[:])
	s.revision(pending, data)
	s.j.Pending = pending
	s.persist()
	s.Close(context.Background())
	s, e = New(o)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Start(context.Background()); e != nil || s.j.Pending != "" || !s.Status().Ready {
		t.Fatal("pending rollback", e)
	}
	s.Close(context.Background())
	b, _ := os.ReadFile(filepath.Join(o.Directory, "journal.json"))
	var j journal
	json.Unmarshal(b, &j)
	j.PID = os.Getpid()
	b, _ = json.Marshal(j)
	os.WriteFile(filepath.Join(o.Directory, "journal.json"), b, 0600)
	if _, e = New(o); e == nil {
		t.Fatal("ambiguous PID accepted")
	}
}
func TestFailedReleaseQuarantinesRollback(t *testing.T) {
	o := options(t)
	var count atomic.Int32
	o.Hooks.Release = func(context.Context) error {
		if count.Add(1) == 2 {
			return errors.New("secret-release")
		}
		return nil
	}
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	s.Apply(context.Background(), []byte(`{"mode":"good"}`))
	old := s.Status().Revision
	if e = s.Apply(context.Background(), []byte(`{"mode":"replacement"}`)); e == nil {
		t.Fatal("release accepted")
	}
	if !s.Status().Ready || s.Status().Revision != old || len(s.j.KnownGood) != 1 || s.j.KnownGood[0] != old {
		t.Fatal("failed release entered LKG")
	}
}
func TestStrictPrivateJournal(t *testing.T) {
	o := options(t)
	os.WriteFile(filepath.Join(o.Directory, "journal.json"), []byte(`{"schema":1,"schema":1,"known_good":[]}`), 0600)
	if _, e := New(o); e == nil {
		t.Fatal("duplicate keys accepted")
	}
	os.Remove(filepath.Join(o.Directory, "journal.json"))
	os.Symlink("/etc/passwd", filepath.Join(o.Directory, "journal.json"))
	if _, e := New(o); e == nil {
		t.Fatal("symlink accepted")
	}
	o = options(t)
	o.Hooks.Probe = nil
	if _, e := New(o); e == nil {
		t.Fatal("missing readiness hook")
	}
}
func TestExitDuringReleaseRequarantines(t *testing.T) {
	o := options(t)
	var q, release atomic.Int32
	var s *Supervisor
	o.Hooks.Quarantine = func(context.Context) error { q.Add(1); return nil }
	o.Hooks.Release = func(context.Context) error {
		if release.Add(1) == 2 {
			s.mu.Lock()
			c := s.child
			s.mu.Unlock()
			_ = c.cmd.Process.Kill()
			<-c.done
		}
		return nil
	}
	var e error
	s, e = New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e = s.Apply(context.Background(), []byte(`{"mode":"good"}`)); e != nil {
		t.Fatal(e)
	}
	old := s.Status().Revision
	if e = s.Apply(context.Background(), []byte(`{"mode":"dies-at-release"}`)); e == nil {
		t.Fatal("release exit accepted")
	}
	if q.Load() < 3 || !s.Status().Ready || s.Status().Revision != old {
		t.Fatal("failed to re-quarantine and recover")
	}
}
func TestStaleExitCannotQuarantineNewGeneration(t *testing.T) {
	o := options(t)
	var q atomic.Int32
	o.Hooks.Quarantine = func(context.Context) error { q.Add(1); return nil }
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	s.Apply(context.Background(), []byte(`{"mode":"good"}`))
	s.mu.Lock()
	c := s.child
	generation := s.generation
	s.mu.Unlock()
	before := q.Load()
	s.gate.Lock()
	done := make(chan bool)
	go func() { current, _ := s.quarantineCurrent(context.Background(), c); done <- current }()
	s.mu.Lock()
	s.generation++
	s.status.Ready = true
	s.mu.Unlock()
	s.gate.Unlock()
	if <-done || q.Load() != before || !s.Status().Ready {
		t.Fatal("stale exit quarantined new generation")
	}
	s.mu.Lock()
	s.generation = generation
	s.mu.Unlock()
}
func TestValidationDeadlineAndRejectedRetention(t *testing.T) {
	o := options(t)
	o.ReadyTimeout = 20 * time.Millisecond
	o.Validator = func(ctx context.Context, path string) error { <-ctx.Done(); return errors.New("secret deadline") }
	s, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	start := time.Now()
	for i := 0; i < 3; i++ {
		b, _ := json.Marshal(map[string]int{"candidate": i})
		if e = s.Apply(context.Background(), b); e == nil {
			t.Fatal("deadline accepted")
		}
	}
	if time.Since(start) > time.Second {
		t.Fatal("validation was not bounded")
	}
	files, _ := os.ReadDir(o.Directory)
	for _, f := range files {
		if hashPattern.MatchString(strings.TrimSuffix(f.Name(), ".json")) {
			t.Fatal("rejected revision retained")
		}
	}
}
