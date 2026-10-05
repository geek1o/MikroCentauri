// Package namespace reserves a bounded, append-only DNS namespace across policy generations.
package namespace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"

	"mikrocentauri.local/core/internal/fakeip"
)

// Four complete name lists (committed and pending Known/Active) at maximum
// capacity must fit even when all DNS names approach the protocol length limit.
const maxBytes = 8 << 20

type Config struct {
	Directory string
	Initial   []string
	Capacity  uint32
}

type Pending struct {
	Revision uint64   `json:"revision"`
	Known    []string `json:"known"`
	Active   []string `json:"active"`
}

type Snapshot struct {
	Revision uint64   `json:"revision"`
	Known    []string `json:"known"`
	Active   []string `json:"active"`
	Pending  *Pending `json:"pending,omitempty"`
}

type journal struct {
	Version  uint32 `json:"version"`
	Capacity uint32 `json:"capacity"`
	Snapshot
}

type Store struct {
	mu     sync.Mutex
	dir    string
	lock   *os.File
	state  journal
	poison error
}

// New opens an exclusive private store. Initial is used only when creating it.
// A recovered pending candidate remains pending until Commit or Abort is called.
func New(config Config) (*Store, error) {
	if config.Capacity == 0 {
		config.Capacity = 32
	}
	if config.Capacity > 4096 || config.Directory == "" {
		return nil, errors.New("invalid namespace configuration")
	}
	dir, err := filepath.Abs(config.Directory)
	if err != nil {
		return nil, err
	}
	if err = privateDirectory(dir); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(dir, "namespace.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "namespace.lock")
	fail := func(e error) (*Store, error) { lock.Close(); return nil, e }
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fail(errors.New("invalid private namespace lock"))
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("namespace already locked: %w", err))
	}
	s := &Store{dir: dir, lock: lock}
	state, exists, err := readJournal(filepath.Join(dir, "namespace.json"))
	if err != nil {
		return fail(err)
	}
	if exists {
		if state.Capacity != config.Capacity {
			return fail(errors.New("namespace capacity mismatch"))
		}
		if err = validate(state); err != nil {
			return fail(err)
		}
		s.state = state
	} else {
		initial, e := canonical(config.Initial)
		if e != nil {
			return fail(e)
		}
		s.state = journal{Version: 1, Capacity: config.Capacity, Snapshot: Snapshot{Revision: 1, Known: initial, Active: append([]string{}, initial...)}}
		if err = validate(s.state); err != nil {
			return fail(err)
		}
		if err = s.write(s.state); err != nil {
			return fail(err)
		}
	}
	return s, nil
}

func privateDirectory(dir string) error {
	parent := filepath.Dir(dir)
	if parent != dir {
		info, err := os.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			if err = privateDirectory(parent); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			// Check every ancestor, not just the final component.
			for p := parent; ; p = filepath.Dir(p) {
				info, err = os.Lstat(p)
				if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return errors.New("namespace directory contains symlink or non-directory")
				}
				if filepath.Dir(p) == p {
					break
				}
			}
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("namespace directory must be private 0700")
	}
	for p := dir; ; p = filepath.Dir(p) {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func canonical(names []string) ([]string, error) {
	result := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		name, err := fakeip.CanonicalDomain(name)
		if err != nil || seen[name] {
			return nil, errors.New("namespace requires unique canonicalizable domains")
		}
		seen[name] = true
		result = append(result, name)
	}
	return result, nil
}

func validate(state journal) error {
	if state.Version != 1 || state.Capacity == 0 || state.Capacity > 4096 || state.Revision == 0 {
		return errors.New("invalid namespace journal header")
	}
	check := func(known, active []string) error {
		if len(known) == 0 || len(known) > int(state.Capacity) || active == nil {
			return errors.New("invalid namespace bounds")
		}
		k, e := canonical(known)
		if e != nil || !reflect.DeepEqual(k, known) {
			return errors.New("invalid known namespace")
		}
		a, e := canonical(active)
		if e != nil || !reflect.DeepEqual(a, active) {
			return errors.New("invalid active namespace")
		}
		set := map[string]bool{}
		for _, n := range known {
			set[n] = true
		}
		for _, n := range active {
			if !set[n] {
				return errors.New("active domain has no reservation")
			}
		}
		return nil
	}
	if err := check(state.Known, state.Active); err != nil {
		return err
	}
	if p := state.Pending; p != nil {
		if state.Revision == math.MaxUint64 || p.Revision != state.Revision+1 || len(p.Known) < len(state.Known) || !reflect.DeepEqual(p.Known[:len(state.Known)], state.Known) {
			return errors.New("invalid pending namespace revision or history")
		}
		return check(p.Known, p.Active)
	}
	return nil
}

func (s *Store) ready() error {
	if s.lock == nil {
		return errors.New("namespace store closed")
	}
	if s.poison != nil {
		return fmt.Errorf("namespace persistence uncertain; reopen required: %w", s.poison)
	}
	return nil
}

func clone(value Snapshot) Snapshot {
	value.Known = append([]string{}, value.Known...)
	value.Active = append([]string{}, value.Active...)
	if value.Pending != nil {
		p := *value.Pending
		p.Known = append([]string{}, p.Known...)
		p.Active = append([]string{}, p.Active...)
		value.Pending = &p
	}
	return value
}

func (s *Store) Snapshot() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return Snapshot{}, err
	}
	return clone(s.state.Snapshot), nil
}

// Preview validates a proposed candidate without changing state or storage.
// It does not reserve the revision: Prepare still performs its own CAS check.
func (s *Store) Preview(expected uint64, active []string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.candidate(expected, active)
	if err != nil {
		return Snapshot{}, err
	}
	return clone(next.Snapshot), nil
}

// Prepare durably reserves newly added names before external allocation occurs.
func (s *Store) Prepare(expected uint64, active []string) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := s.candidate(expected, active)
	if err != nil {
		return Snapshot{}, err
	}
	return s.persist(next)
}

// candidate requires mu and performs all validation without mutating the store.
func (s *Store) candidate(expected uint64, active []string) (journal, error) {
	if err := s.ready(); err != nil {
		return journal{}, err
	}
	if s.state.Pending != nil || expected != s.state.Revision || expected == math.MaxUint64 {
		return journal{}, errors.New("namespace revision conflict or unresolved pending candidate")
	}
	names, err := canonical(active)
	if err != nil {
		return journal{}, err
	}
	next := s.state
	next.Snapshot = clone(s.state.Snapshot)
	known := append([]string{}, next.Known...)
	set := map[string]bool{}
	for _, n := range known {
		set[n] = true
	}
	for _, n := range names {
		if !set[n] {
			known = append(known, n)
			set[n] = true
		}
	}
	next.Pending = &Pending{Revision: expected + 1, Known: known, Active: names}
	if err := validate(next); err != nil {
		return journal{}, err
	}
	return next, nil
}

// Commit acknowledges successful external admission of the pending revision.
// The caller must independently verify its engine/publication receipt first.
func (s *Store) Commit(expected uint64) (Snapshot, error) { return s.resolve(expected, true) }

// Abort consumes the revision and retains all pending reservations, including
// names that an external allocator may already have assigned before failure.
func (s *Store) Abort(expected uint64) (Snapshot, error) { return s.resolve(expected, false) }

func (s *Store) resolve(expected uint64, commit bool) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return Snapshot{}, err
	}
	p := s.state.Pending
	if p == nil || p.Revision != expected {
		return Snapshot{}, errors.New("namespace pending revision mismatch")
	}
	next := s.state
	next.Snapshot = clone(s.state.Snapshot)
	next.Revision = p.Revision
	next.Known = append([]string{}, p.Known...)
	if commit {
		next.Active = append([]string{}, p.Active...)
	}
	next.Pending = nil
	return s.persist(next)
}

func (s *Store) persist(next journal) (Snapshot, error) {
	if err := validate(next); err != nil {
		return Snapshot{}, err
	}
	if err := s.write(next); err != nil {
		s.poison = err
		return Snapshot{}, err
	}
	s.state = next
	return clone(next.Snapshot), nil
}

func (s *Store) write(next journal) error {
	// Refuse a replaced destination instead of silently overwriting an unsafe
	// entry. The private directory and process lock protect cooperative writers.
	path := filepath.Join(s.dir, "namespace.json")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxBytes {
			return errors.New("invalid namespace destination")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxBytes {
		return errors.New("namespace journal size limit")
	}
	f, err := os.CreateTemp(s.dir, ".namespace-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readJournal(path string) (journal, bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return journal{}, false, nil
	}
	if err != nil {
		return journal{}, false, err
	}
	f := os.NewFile(uintptr(fd), "namespace.json")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxBytes {
		return journal{}, false, errors.New("invalid private namespace journal")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return journal{}, false, errors.New("namespace read failure or size limit")
	}
	if err = uniqueKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return journal{}, false, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var state journal
	if err = d.Decode(&state); err != nil {
		return journal{}, false, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return journal{}, false, errors.New("namespace trailing data")
	}
	return state, true, nil
}

func uniqueKeys(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			k, ok := key.(string)
			if !ok || seen[k] {
				return errors.New("duplicate namespace JSON member")
			}
			seen[k] = true
			if err = uniqueKeys(d); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for d.More() {
			if err = uniqueKeys(d); err != nil {
				return err
			}
		}
	} else {
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
