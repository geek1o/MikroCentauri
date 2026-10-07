package namespace

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
)

func TestPreviewPureAndPrepareRechecksRevision(t *testing.T) {
	c := config(t, 2)
	s := open(t, c)
	before, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Directory, "namespace.json")
	journalBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		revision uint64
		active   []string
	}{
		{1, []string{"selected.test", "Selected.test."}},
		{1, []string{"selected.test", "second.test", "third.test"}},
		{0, []string{"second.test"}},
		{1, []string{"invalid/name"}},
	} {
		if _, err := s.Preview(input.revision, input.active); err == nil {
			t.Fatal("invalid preview accepted", input)
		}
		after, err := s.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("preview changed or poisoned state", after, err)
		}
		journalAfter, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(journalBefore, journalAfter) {
			t.Fatal("preview wrote journal", err)
		}
	}
	preview, err := s.Preview(1, []string{"Second.TEST."})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.Snapshot()
	journalAfter, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) || !bytes.Equal(journalBefore, journalAfter) {
		t.Fatal("valid preview mutated store")
	}
	prepared, err := s.Prepare(1, []string{"Second.TEST."})
	if err != nil || !reflect.DeepEqual(preview, prepared) {
		t.Fatal("preview differs from candidate", preview, prepared, err)
	}
	preview.Pending.Known[0] = "tampered.test"
	stored, _ := s.Snapshot()
	if stored.Pending.Known[0] != "selected.test" {
		t.Fatal("preview aliases state")
	}
	if _, err := s.Preview(1, []string{"selected.test"}); err == nil {
		t.Fatal("pending state preview accepted")
	}
	if _, err := s.Commit(2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare(1, []string{"second.test"}); err == nil {
		t.Fatal("old preview bypassed CAS")
	}
}

func config(t *testing.T, capacity uint32) Config {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return Config{Directory: filepath.Join(dir, "policy"), Initial: []string{"Selected.test."}, Capacity: capacity}
}

func open(t *testing.T, c Config) *Store {
	t.Helper()
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestHistoryAcrossRetireReactivateAndRestart(t *testing.T) {
	c := config(t, 3)
	s := open(t, c)
	p, err := s.Prepare(1, []string{"Second.TEST", "selected.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Pending.Known, []string{"selected.test", "second.test"}) {
		t.Fatal(p)
	}
	if _, err = s.Commit(1); err == nil {
		t.Fatal("accepted stale receipt")
	}
	if _, err = s.Commit(2); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Prepare(2, []string{}); err != nil {
		t.Fatal(err)
	}
	retired, err := s.Commit(3)
	if err != nil || len(retired.Active) != 0 || len(retired.Known) != 2 {
		t.Fatal(retired, err)
	}
	if _, err = s.Prepare(3, []string{"second.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Commit(4); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open(t, c)
	got, err := s.Snapshot()
	if err != nil || got.Revision != 4 || !reflect.DeepEqual(got.Known, retired.Known) || !reflect.DeepEqual(got.Active, []string{"second.test"}) {
		t.Fatal(got, err)
	}
	got.Known[0] = "tampered.test"
	again, _ := s.Snapshot()
	if again.Known[0] != "selected.test" {
		t.Fatal("snapshot aliases internal state")
	}
}

func TestAbortRetainsReservationAndConsumesCapacity(t *testing.T) {
	c := config(t, 2)
	s := open(t, c)
	if _, err := s.Prepare(1, []string{"second.test"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open(t, c)
	pending, _ := s.Snapshot()
	if pending.Pending == nil || pending.Revision != 1 {
		t.Fatal(pending)
	}
	if _, err := s.Prepare(1, []string{"third.test"}); err == nil {
		t.Fatal("overwrote unresolved restart")
	}
	if _, err := s.Abort(1); err == nil {
		t.Fatal("accepted wrong abort revision")
	}
	aborted, err := s.Abort(2)
	if err != nil || aborted.Revision != 2 || !reflect.DeepEqual(aborted.Active, []string{"selected.test"}) || len(aborted.Known) != 2 {
		t.Fatal(aborted, err)
	}
	if _, err = s.Prepare(1, []string{"second.test"}); err == nil {
		t.Fatal("accepted replay")
	}
	if _, err = s.Prepare(2, []string{"third.test"}); err == nil {
		t.Fatal("recycled reservation")
	}
	if _, err = s.Prepare(2, []string{"second.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Commit(3); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCASAndExclusiveLock(t *testing.T) {
	c := config(t, 32)
	s := open(t, c)
	if other, err := New(c); err == nil {
		other.Close()
		t.Fatal("second process store accepted")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Prepare(1, []string{"second.test"}); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
	if _, err := s.Commit(2); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := s.Snapshot(); err == nil {
		t.Fatal("closed store accepted")
	}
}

func TestInvalidInputAndCapacity(t *testing.T) {
	for _, initial := range [][]string{nil, {}, {"a.test", "A.test."}, {"bad/name"}} {
		c := config(t, 32)
		c.Initial = initial
		if s, err := New(c); err == nil {
			s.Close()
			t.Fatal(initial)
		}
	}
	c := config(t, 4097)
	if s, err := New(c); err == nil {
		s.Close()
		t.Fatal("oversized capacity")
	}
	s := open(t, config(t, 32))
	for _, active := range [][]string{{"Second.test", "second.test."}, {"bad name"}} {
		if _, err := s.Prepare(1, active); err == nil {
			t.Fatal(active)
		}
	}
}

func TestRefuseCorruptJournal(t *testing.T) {
	for _, mutate := range []func(journal) []byte{
		func(j journal) []byte { return []byte(`{"version":1,"version":1}`) },
		func(j journal) []byte { j.Known = []string{"SELECTED.test"}; b, _ := json.Marshal(j); return b },
		func(j journal) []byte { j.Active = []string{"unknown.test"}; b, _ := json.Marshal(j); return b },
		func(j journal) []byte {
			j.Pending = &Pending{Revision: 2, Known: []string{"second.test", "selected.test"}, Active: []string{}}
			b, _ := json.Marshal(j)
			return b
		},
		func(j journal) []byte {
			j.Pending = &Pending{Revision: 3, Known: j.Known, Active: j.Active}
			b, _ := json.Marshal(j)
			return b
		},
		func(j journal) []byte { b, _ := json.Marshal(j); return append(b, []byte(" {}")...) },
		func(j journal) []byte {
			return []byte(`{"version":1,"capacity":32,"revision":1,"known":["selected.test"],"active":[],"extra":1}`)
		},
	} {
		c := config(t, 32)
		s := open(t, c)
		state := s.state
		s.Close()
		if err := os.WriteFile(filepath.Join(c.Directory, "namespace.json"), mutate(state), 0600); err != nil {
			t.Fatal(err)
		}
		if again, err := New(c); err == nil {
			again.Close()
			t.Fatal("corrupt journal accepted")
		}
	}
}

func TestRefuseSymlinksModesOversizeAndFIFO(t *testing.T) {
	for _, kind := range []string{"journal-symlink", "lock-symlink", "journal-mode", "oversize", "directory-symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			c := config(t, 32)
			s := open(t, c)
			s.Close()
			path := filepath.Join(c.Directory, "namespace.json")
			switch kind {
			case "journal-symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "lock-symlink":
				path = filepath.Join(c.Directory, "namespace.lock")
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "journal-mode":
				os.Chmod(path, 0644)
			case "oversize":
				f, err := os.OpenFile(path, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				f.Truncate(maxBytes + 1)
				f.Close()
			case "directory-symlink":
				os.Rename(c.Directory, c.Directory+".real")
				os.Symlink(c.Directory+".real", c.Directory)
			case "fifo":
				os.Remove(path)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if again, err := New(c); err == nil {
				again.Close()
				t.Fatal("unsafe path accepted")
			}
		})
	}
}

func TestPersistenceFailurePoisonsUntilReopen(t *testing.T) {
	c := config(t, 32)
	s := open(t, c)
	// Replacing the destination with a directory forces a durable-write failure
	// independently of root privileges or filesystem permission emulation.
	path := filepath.Join(c.Directory, "namespace.json")
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare(1, []string{"second.test"}); err == nil {
		t.Fatal("failed write accepted")
	}
	if _, err := s.Snapshot(); err == nil {
		t.Fatal("uncertain store remained usable")
	}
	if _, err := s.Prepare(1, []string{"second.test"}); err == nil {
		t.Fatal("poisoned store mutated")
	}
	s.Close()
	os.Remove(path)
	os.Rename(path+".saved", path)
	s = open(t, c)
	state, err := s.Snapshot()
	if err != nil || state.Revision != 1 || state.Pending != nil {
		t.Fatal(state, err)
	}
}
