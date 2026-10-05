package coreactivation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/singbox"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/activation"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/supervisor"
)

type TransitionOptions struct {
	Directory       string
	Store           *namespace.Store
	Activation      Options
	Process         supervisor.Options
	Model           coreconfig.Model
	ResolveRuleSets func(context.Context, coreconfig.Model) ([]rulesets.Artifact, error)
}
type TransitionStatus struct {
	Ready     bool
	Namespace namespace.Snapshot
	Process   supervisor.Status
	Traffic   Status
}

// Transition is the single owner of model, namespace, supervisor and external
// DNS publication. All public lifecycle methods serialize against Check/Close.
// Callers must not independently write the Store or invoke its runtime methods.
type Transition struct {
	op               sync.Mutex
	mu               sync.Mutex
	options          TransitionOptions
	directory        string
	lock             *os.File
	poisoned, closed bool
	published        bool
	transitioning    atomic.Bool
	dns              *dnsgate.Switcher
	adapter          *Adapter
	process          *supervisor.Supervisor
	controller       *activation.Controller
}
type transitionRecord struct {
	Snapshot  namespace.Snapshot  `json:"snapshot"`
	Model     json.RawMessage     `json:"model"`
	Artifacts []rulesets.Artifact `json:"artifacts,omitempty"`
}
type transitionView struct {
	store   *namespace.Store
	desired namespace.Snapshot
}

func committedView(s namespace.Snapshot) namespace.Snapshot {
	s.Pending = nil
	s.Known = append([]string{}, s.Known...)
	s.Active = append([]string{}, s.Active...)
	return s
}
func (v transitionView) Snapshot() (namespace.Snapshot, error) {
	actual, err := v.store.Snapshot()
	if err != nil {
		return namespace.Snapshot{}, err
	}
	if reflect.DeepEqual(committedView(actual), v.desired) {
		return committedView(v.desired), nil
	}
	if actual.Pending != nil {
		pending := namespace.Snapshot{Revision: actual.Pending.Revision, Known: actual.Pending.Known, Active: actual.Pending.Active}
		if reflect.DeepEqual(pending, v.desired) {
			return committedView(v.desired), nil
		}
	}
	return namespace.Snapshot{}, errors.New("namespace is outside staged view")
}
func snapshotKey(s namespace.Snapshot) string {
	b, _ := json.Marshal(committedView(s))
	return digest(b)
}
func NewTransition(o TransitionOptions) (*Transition, error) {
	if o.Store == nil || o.Directory == "" {
		return nil, errors.New("transition requires durable namespace and registry")
	}
	dir, err := filepath.Abs(o.Directory)
	if err != nil || checkPath(dir) != nil {
		return nil, errors.New("unsafe transition registry")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("transition registry unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("transition registry must be private")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "transition.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("transition lock unavailable")
	}
	info, err = lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("transition registry already owned or unsafe")
	}
	t := &Transition{options: o, directory: dir, lock: lock, dns: dnsgate.NewSwitcher(nil)}
	if t.options.Activation.CachePath == "" {
		t.options.Activation.CachePath = filepath.Join(dir, "engine-cache.db")
	}
	fail := func(err error) (*Transition, error) {
		if t.process != nil {
			t.process.Close(context.Background())
		}
		if t.adapter != nil {
			t.adapter.Close(context.Background())
		}
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, err
	}
	actual, err := o.Store.Snapshot()
	if err != nil {
		return fail(err)
	}
	base := committedView(actual)
	path := t.recordPath(base)
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		if err = t.save(context.Background(), base, o.Model); err != nil {
			return fail(err)
		}
	}
	model, err := t.load(base)
	if err != nil {
		return fail(err)
	}
	a, err := t.newAdapter(context.Background(), base, model)
	if err != nil {
		return fail(err)
	}
	t.adapter = a
	processOptions := o.Process
	processOptions.Semantic = func(data []byte) error {
		a := t.currentAdapter()
		if a == nil {
			return errors.New("transition adapter unavailable")
		}
		return a.Semantic(data)
	}
	processOptions.Hooks = supervisor.Hooks{
		Quarantine: func(ctx context.Context) error {
			t.dns.Hold()
			t.mu.Lock()
			t.published = false
			t.mu.Unlock()
			a := t.currentAdapter()
			if a == nil {
				return t.options.Activation.Barrier.Quarantine(ctx)
			}
			return a.Quarantine(ctx)
		},
		Prepare: func(ctx context.Context, path string) error {
			a := t.currentAdapter()
			if a == nil {
				return errors.New("transition adapter absent")
			}
			return a.prepare(ctx, path)
		},
		Probe: func(ctx context.Context, path string) error {
			a := t.currentAdapter()
			if a == nil {
				return errors.New("transition adapter absent")
			}
			return a.probe(ctx, path)
		},
		Release: func(ctx context.Context) error {
			a := t.currentAdapter()
			if a == nil {
				return errors.New("transition adapter absent")
			}
			actual, err := o.Store.Snapshot()
			if err != nil || actual.Pending != nil || !reflect.DeepEqual(actual, a.base) {
				return errors.New("namespace commit required before forwarding release")
			}
			if err := a.release(ctx); err != nil {
				return err
			}
			if !t.transitioning.Load() {
				return t.publish(a)
			}
			return nil
		},
	}
	t.process, err = supervisor.New(processOptions)
	if err != nil {
		return fail(err)
	}
	t.controller, err = activation.New(o.Store, t)
	if err != nil {
		return fail(err)
	}
	return t, nil
}
func (t *Transition) currentAdapter() *Adapter { t.mu.Lock(); defer t.mu.Unlock(); return t.adapter }
func (t *Transition) recordPath(s namespace.Snapshot) string {
	return filepath.Join(t.directory, snapshotKey(s)+".snapshot-model.json")
}
func (t *Transition) ports(ctx context.Context, m coreconfig.Model) (coreconfig.Options, error) {
	ports := t.options.Activation.Ports
	ports.CachePath = t.options.Activation.CachePath
	if t.options.ResolveRuleSets != nil {
		artifacts, err := t.options.ResolveRuleSets(ctx, m)
		if err != nil {
			return ports, errors.New("trusted rule-set artifacts unavailable")
		}
		ports.RuleSets = artifacts
	}
	return ports, nil
}
func (t *Transition) save(ctx context.Context, s namespace.Snapshot, m coreconfig.Model) error {
	if t.poisoned {
		return errors.New("transition durability unresolved; reopen required")
	}
	ports, err := t.ports(ctx, m)
	if err != nil {
		return err
	}
	if _, err = coreconfig.GenerateForNamespace(m, s, ports); err != nil {
		return err
	}
	artifacts, err := t.pinArtifacts(ports.RuleSets)
	if err != nil {
		return err
	}
	ports.RuleSets = artifacts
	if _, err = coreconfig.GenerateForNamespace(m, s, ports); err != nil {
		return err
	}
	encoded, err := encodeModel(m)
	if err != nil {
		return err
	}
	record, err := json.Marshal(transitionRecord{Snapshot: committedView(s), Model: encoded, Artifacts: artifacts})
	if err != nil || len(record) > 4<<20 {
		return errors.New("snapshot model exceeds bounds")
	}
	if err := t.privateRegistry(); err != nil {
		return err
	}
	if existing, err := readPrivate(t.recordPath(s)); err == nil {
		if !bytes.Equal(existing, record) {
			return errors.New("snapshot source model is immutable")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errors.New("existing snapshot source unavailable")
	}
	candidate, err := coreconfig.GenerateForNamespace(m, s, ports)
	if err != nil {
		return err
	}
	if err = t.checkCandidate(ctx, candidate); err != nil {
		return err
	}
	if err = config.WriteAtomic(t.recordPath(s), record); err != nil {
		t.poisoned = true
		return errors.New("snapshot model persistence failed")
	}
	return nil
}
func (t *Transition) readRecord(s namespace.Snapshot) (transitionRecord, error) {
	if err := t.privateRegistry(); err != nil {
		return transitionRecord{}, err
	}
	raw, err := readPrivate(t.recordPath(s))
	if err != nil {
		return transitionRecord{}, errors.New("durable snapshot model unavailable")
	}
	if transitionJSON(raw) != nil {
		return transitionRecord{}, errors.New("ambiguous snapshot source JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var record transitionRecord
	if d.Decode(&record) != nil {
		return record, errors.New("invalid snapshot model")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF || !reflect.DeepEqual(record.Snapshot, s) {
		return record, errors.New("snapshot model identity differs")
	}
	for _, artifact := range record.Artifacts {
		if artifact.Validate() != nil || filepath.Dir(artifact.Path) != filepath.Join(t.directory, "artifacts") {
			return record, errors.New("pinned rule-set integrity denied")
		}
	}
	return record, nil
}
func (t *Transition) load(s namespace.Snapshot) (coreconfig.Model, error) {
	record, err := t.readRecord(s)
	if err != nil {
		return coreconfig.Model{}, err
	}
	model, err := coreconfig.Decode(record.Model)
	if err != nil {
		return coreconfig.Model{}, errors.New("invalid durable source model")
	}
	return model, nil
}
func (t *Transition) frozenPorts(s namespace.Snapshot) (coreconfig.Options, error) {
	record, err := t.readRecord(s)
	if err != nil {
		return coreconfig.Options{}, err
	}
	ports := t.options.Activation.Ports
	ports.CachePath = t.options.Activation.CachePath
	ports.RuleSets = record.Artifacts
	return ports, nil
}
func (t *Transition) pinArtifacts(artifacts []rulesets.Artifact) ([]rulesets.Artifact, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	directory := filepath.Join(t.directory, "artifacts")
	if checkPath(directory) != nil {
		return nil, errors.New("unsafe artifact registry")
	}
	if os.MkdirAll(directory, 0700) != nil {
		return nil, errors.New("artifact registry unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("artifact registry must be private")
	}
	pinned := make([]rulesets.Artifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Validate() != nil {
			return nil, errors.New("trusted artifact integrity denied")
		}
		data, err := readPrivate(artifact.Path)
		if err != nil {
			return nil, errors.New("trusted artifact unavailable")
		}
		candidate := rulesets.Artifact{ID: artifact.ID, SHA256: artifact.SHA256, Path: filepath.Join(directory, artifact.SHA256+".srs")}
		if _, err = os.Lstat(candidate.Path); os.IsNotExist(err) {
			if config.WriteAtomic(candidate.Path, data) != nil {
				t.poisoned = true
				return nil, errors.New("artifact persistence failed")
			}
		}
		if candidate.Validate() != nil {
			return nil, errors.New("pinned artifact integrity denied")
		}
		pinned = append(pinned, candidate)
	}
	return pinned, nil
}
func (t *Transition) newAdapter(ctx context.Context, s namespace.Snapshot, m coreconfig.Model) (*Adapter, error) {
	options := t.options.Activation
	options.Namespace = transitionView{store: t.options.Store, desired: committedView(s)}
	options.Directory = filepath.Join(t.directory, "snapshots", snapshotKey(s))
	ports, err := t.frozenPorts(s)
	if err != nil {
		return nil, err
	}
	options.Ports = ports
	a, err := New(options)
	if err != nil {
		return nil, err
	}
	if _, err = a.Register(m); err != nil {
		a.Close(ctx)
		return nil, err
	}
	return a, nil
}
func (t *Transition) Apply(ctx context.Context, revision uint64, active []string, m coreconfig.Model) (namespace.Snapshot, error) {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return namespace.Snapshot{}, errors.New("transition closed or durability unresolved")
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	candidate, err := t.options.Store.Preview(revision, active)
	if err != nil {
		return namespace.Snapshot{}, err
	}
	desired := namespace.Snapshot{Revision: candidate.Pending.Revision, Known: candidate.Pending.Known, Active: candidate.Pending.Active}
	if err = t.save(ctx, desired, m); err != nil {
		return namespace.Snapshot{}, errors.Join(err, t.prune())
	}
	t.transitioning.Store(true)
	defer t.transitioning.Store(false)
	result, err := t.controller.Apply(ctx, revision, active)
	return result, errors.Join(err, t.prune())
}
func (t *Transition) Recover(ctx context.Context) (namespace.Snapshot, error) {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return namespace.Snapshot{}, errors.New("transition closed or durability unresolved")
	}
	t.transitioning.Store(true)
	defer t.transitioning.Store(false)
	result, err := t.controller.Recover(ctx)
	return result, errors.Join(err, t.prune())
}

// Runtime methods are invoked by the serialized activation controller only.
func (t *Transition) Validate(ctx context.Context, s namespace.Snapshot) error {
	if s.Pending != nil {
		return errors.New("pending namespace requires recovery")
	}
	model, err := t.load(s)
	if err != nil {
		return err
	}
	ports, err := t.frozenPorts(s)
	if err != nil {
		return err
	}
	expected, err := coreconfig.GenerateForNamespace(model, s, ports)
	if err != nil {
		return err
	}
	status := t.process.Status()
	if status.Live && status.Revision != digest(expected) {
		return errors.New("live process differs from committed source model")
	}
	return ctx.Err()
}
func (t *Transition) Quarantine(ctx context.Context) error {
	t.dns.Hold()
	t.mu.Lock()
	t.published = false
	t.mu.Unlock()
	if t.process != nil {
		return t.process.Stop(ctx)
	}
	a := t.currentAdapter()
	if a != nil {
		return a.Quarantine(ctx)
	}
	return t.options.Activation.Barrier.Quarantine(ctx)
}
func (t *Transition) Stage(ctx context.Context, s namespace.Snapshot) error {
	t.dns.Hold()
	if s.Pending != nil {
		return errors.New("stage requires normalized namespace")
	}
	model, err := t.load(s)
	if err != nil {
		return err
	}
	old := t.currentAdapter()
	if old != nil {
		if err = old.Close(ctx); err != nil {
			return err
		}
	}
	t.mu.Lock()
	t.adapter = nil
	t.mu.Unlock()
	a, err := t.newAdapter(ctx, s, model)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.adapter = a
	t.mu.Unlock()
	candidate, err := a.Register(model)
	if err != nil {
		return err
	}
	return t.process.Stage(ctx, candidate)
}
func (t *Transition) Verify(ctx context.Context, s namespace.Snapshot) error {
	a := t.currentAdapter()
	if a == nil || !reflect.DeepEqual(a.base, s) {
		return errors.New("staged namespace differs")
	}
	return t.process.VerifyStaged(ctx)
}
func (t *Transition) Release(ctx context.Context, s namespace.Snapshot) error {
	actual, err := t.options.Store.Snapshot()
	if err != nil || actual.Pending != nil || !reflect.DeepEqual(actual, s) {
		return errors.New("actual namespace is not committed")
	}
	a := t.currentAdapter()
	if a == nil || !reflect.DeepEqual(a.base, s) {
		return errors.New("release namespace differs")
	}
	if err = t.process.CommitStaged(ctx); err != nil {
		return err
	}
	return t.publish(a)
}
func (t *Transition) publish(a *Adapter) error {
	if err := t.dns.Install(a.Handler()); err != nil {
		return err
	}
	if err := t.dns.Release(); err != nil {
		return err
	}
	t.mu.Lock()
	t.published = true
	t.mu.Unlock()
	return nil
}

// Hold closes publication and stops the child without discarding durable intent.
// A later Recover must reprove the generation before opening traffic.
func (t *Transition) Hold(ctx context.Context) error {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed {
		return errors.New("transition closed")
	}
	return t.Quarantine(ctx)
}
func (t *Transition) Handler() dnsgate.Handler { return t.dns }
func (t *Transition) Status() TransitionStatus {
	s := TransitionStatus{}
	s.Namespace, _ = t.options.Store.Snapshot()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.process != nil {
		s.Process = t.process.Status()
	}
	if t.adapter != nil {
		s.Traffic = t.adapter.Status()
	}
	s.Ready = !t.closed && t.published && s.Namespace.Pending == nil && s.Process.Ready && s.Process.Live && s.Traffic.Ready && s.Traffic.Admission.Admitted
	return s
}
func (t *Transition) Check(ctx context.Context) error {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed {
		return errors.New("transition closed")
	}
	actual, err := t.options.Store.Snapshot()
	if err != nil || actual.Pending != nil {
		t.dns.Hold()
		return errors.Join(errors.New("namespace not committed"), t.Quarantine(ctx))
	}
	a := t.currentAdapter()
	if a == nil {
		return errors.New("transition adapter absent")
	}
	if err = a.Check(ctx); err != nil {
		t.dns.Hold()
		return errors.Join(err, t.process.Stop(ctx))
	}
	return nil
}
func (t *Transition) Close(ctx context.Context) error {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed {
		return nil
	}
	t.dns.Hold()
	processErr := t.process.Close(ctx)
	a := t.currentAdapter()
	var adapterErr error
	if a != nil {
		adapterErr = a.Close(ctx)
	}
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	syscall.Flock(int(t.lock.Fd()), syscall.LOCK_UN)
	t.lock.Close()
	return errors.Join(processErr, adapterErr)
}

var _ activation.Runtime = (*Transition)(nil)

func (t *Transition) checkCandidate(ctx context.Context, data []byte) error {
	file, err := os.CreateTemp(t.directory, ".syntax-")
	if err != nil {
		return errors.New("candidate preflight unavailable")
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("candidate preflight write failed")
	}
	timeout := t.options.Process.ReadyTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	validator := t.options.Process.Validator
	if validator == nil {
		validator = func(ctx context.Context, path string) error {
			return singbox.Check(ctx, t.options.Process.Binary, path)
		}
	}
	if validator(bounded, path) != nil {
		return errors.New("candidate core validation failed before quarantine")
	}
	return bounded.Err()
}

// Keep source envelopes for every retained supervisor revision, committed and
// pending namespace, and at most five recent speculative candidates. The shared
// engine cache and append-only namespace/alias ledgers are never pruned.
func (t *Transition) prune() error {
	if err := t.privateRegistry(); err != nil {
		return err
	}
	if t.poisoned {
		return errors.New("transition retention blocked by uncertain durability")
	}
	files, err := os.ReadDir(t.directory)
	if err != nil {
		return errors.New("transition retention read failed")
	}
	type item struct {
		key    string
		record transitionRecord
		hash   string
	}
	records := []item{}
	keep := map[string]bool{}
	actual, err := t.options.Store.Snapshot()
	if err != nil {
		return err
	}
	keep[snapshotKey(actual)] = true
	if actual.Pending != nil {
		keep[snapshotKey(namespace.Snapshot{Revision: actual.Pending.Revision, Known: actual.Pending.Known, Active: actual.Pending.Active})] = true
	}
	if a := t.currentAdapter(); a != nil {
		keep[snapshotKey(a.base)] = true
	}
	hashes := map[string]bool{}
	for _, hash := range t.process.RetainedRevisions() {
		hashes[hash] = true
	}
	for _, file := range files {
		key, ok := strings.CutSuffix(file.Name(), ".snapshot-model.json")
		if !ok || len(key) != 64 {
			continue
		}
		raw, err := readPrivate(filepath.Join(t.directory, file.Name()))
		if err != nil {
			return errors.New("unsafe retention source")
		}
		var record transitionRecord
		if json.Unmarshal(raw, &record) != nil || snapshotKey(record.Snapshot) != key {
			return errors.New("invalid retention source")
		}
		model, err := t.load(record.Snapshot)
		if err != nil {
			return err
		}
		ports, err := t.frozenPorts(record.Snapshot)
		if err != nil {
			return err
		}
		config, err := coreconfig.GenerateForNamespace(model, record.Snapshot, ports)
		if err != nil {
			return err
		}
		hash := digest(config)
		records = append(records, item{key, record, hash})

	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].record.Snapshot.Revision != records[j].record.Snapshot.Revision {
			return records[i].record.Snapshot.Revision > records[j].record.Snapshot.Revision
		}
		return records[i].key < records[j].key
	})
	represented := map[string]bool{}
	for i, record := range records {
		if hashes[record.hash] && !represented[record.hash] {
			keep[record.key] = true
			represented[record.hash] = true
		}
		if i < 5 {
			keep[record.key] = true
		}
	}
	artifacts := map[string]bool{}
	for _, record := range records {
		if keep[record.key] {
			for _, artifact := range record.record.Artifacts {
				artifacts[artifact.Path] = true
			}
			continue
		}
		path := t.recordPath(record.record.Snapshot)
		if os.Remove(path) != nil {
			return errors.New("source retention removal failed")
		}
		directory := filepath.Join(t.directory, "snapshots", record.key)
		if err = removeSnapshotRegistry(directory); err != nil {
			return err
		}
	}
	artifactDirectory := filepath.Join(t.directory, "artifacts")
	entries, err := os.ReadDir(artifactDirectory)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("artifact retention unavailable")
	}
	for _, entry := range entries {
		hash, ok := strings.CutSuffix(entry.Name(), ".srs")
		if !ok || len(hash) != 64 {
			continue
		}
		path := filepath.Join(artifactDirectory, entry.Name())
		if artifacts[path] {
			continue
		}
		if _, err = readPrivate(path); err != nil {
			return errors.New("unsafe retained artifact")
		}
		if os.Remove(path) != nil {
			return errors.New("artifact retention failed")
		}
	}
	dir, err := os.Open(t.directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if dir.Sync() != nil {
		t.poisoned = true
		return errors.New("source retention durability unresolved")
	}
	return nil
}
func removeSnapshotRegistry(directory string) error {
	if checkPath(directory) != nil {
		return errors.New("unsafe old snapshot registry")
	}
	info, statErr := os.Lstat(directory)
	if statErr == nil && (!info.IsDir() || info.Mode().Perm() != 0700) {
		return errors.New("unsafe old snapshot directory")
	}
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		hash, model := strings.CutSuffix(entry.Name(), ".model.json")
		if entry.Name() != "registry.lock" && (!model || len(hash) != 64) {
			return errors.New("foreign file in old snapshot registry")
		}
		if _, err := readPrivate(filepath.Join(directory, entry.Name())); err != nil {
			return errors.New("unsafe old snapshot registry file")
		}
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	return os.Remove(directory)
}

func transitionJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var read func(int) error
	read = func(depth int) error {
		if depth > 64 {
			return errors.New("snapshot JSON too deep")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return errors.New("duplicate snapshot key")
				}
				seen[key] = true
				if err = read(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err = read(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid snapshot JSON")
		}
		_, err = decoder.Token()
		return err
	}
	if err := read(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing snapshot JSON")
	}
	return nil
}

func (t *Transition) privateRegistry() error {
	info, err := os.Lstat(t.directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || checkPath(t.directory) != nil {
		return errors.New("transition registry privacy changed")
	}
	return nil
}
