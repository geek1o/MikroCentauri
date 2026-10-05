package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestStagedCommitAndRecovery(t *testing.T) {
	o := options(t)
	var releases atomic.Int32
	var externalCommit atomic.Bool
	o.Hooks.Release = func(context.Context) error {
		if !externalCommit.Load() {
			return errors.New("external policy uncommitted")
		}
		var j journal
		b, err := os.ReadFile(filepath.Join(o.Directory, "journal.json"))
		if err != nil || json.Unmarshal(b, &j) != nil || j.Active == "" || j.Pending != "" {
			t.Error("release before commit")
		}
		releases.Add(1)
		return nil
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	data := []byte(`{"mode":"staged"}`)
	if err = s.Stage(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.Ready || !st.Live || st.State != "staged" || releases.Load() != 0 {
		t.Fatal(st)
	}
	if err = s.VerifyStaged(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitStaged(context.Background()); err == nil || s.Status().Live || releases.Load() != 0 {
		t.Fatal("uncommitted policy released", err)
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err = New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err = s.Start(context.Background()); err == nil {
		t.Fatal("staged intent reopened without external commit")
	}
	if err = s.Stage(context.Background(), []byte(`{"mode":"different"}`)); err == nil {
		t.Fatal("pending intent replaced")
	}
	if err = s.Stage(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	externalCommit.Store(true)
	if err = s.CommitStaged(context.Background()); err != nil || !s.Status().Ready || releases.Load() != 1 {
		t.Fatal(err, s.Status())
	}
}

func TestStagedCrashNeverRestartsOldPolicy(t *testing.T) {
	o := options(t)
	var releases atomic.Int32
	o.Hooks.Release = func(context.Context) error { releases.Add(1); return nil }
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if err = s.Apply(context.Background(), []byte(`{"mode":"old"}`)); err != nil {
		t.Fatal(err)
	}
	if err = s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = s.Stage(context.Background(), []byte(`{"mode":"new"}`)); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Kill(s.Status().PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.Status().State != "pending-recovery" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := s.Status(); st.Live || st.Ready || st.State != "pending-recovery" || releases.Load() != 1 {
		t.Fatal("staged crash reopened old policy", st)
	}
	if err = s.CommitStaged(context.Background()); err == nil {
		t.Fatal("dead staged process committed")
	}
}
