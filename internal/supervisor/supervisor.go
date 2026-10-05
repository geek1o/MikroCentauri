// Package supervisor owns a checked sing-box process and durable configuration revisions.
// Hooks must quarantine traffic before replacement and release it only after durable commit.
package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/singbox"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Hooks execute serially for each lifecycle operation. Each callback must honor
// cancellation and its deadline; Probe proves dataplane readiness, not only process liveness.
type Hooks struct {
	Quarantine func(context.Context) error
	Prepare    func(context.Context, string) error
	Probe      func(context.Context, string) error
	Release    func(context.Context) error
}
type Options struct {
	Binary, Directory                                     string
	KeepRevisions                                         int
	StopTimeout, ReadyTimeout, BackoffInitial, BackoffMax time.Duration
	CrashLimit                                            int
	CrashWindow                                           time.Duration
	Validator                                             func(context.Context, string) error
	Semantic                                              func([]byte) error
	Hooks                                                 Hooks
}
type Status struct {
	Live, Ready     bool
	PID             int
	Revision, State string
	Restarts        int
	LastError       string
}
type Event struct {
	Time     time.Time `json:"time"`
	Code     string    `json:"code"`
	Revision string    `json:"revision,omitempty"`
}
type journal struct {
	Schema    int      `json:"schema"`
	Active    string   `json:"active,omitempty"`
	Pending   string   `json:"pending,omitempty"`
	PID       int      `json:"pid,omitempty"`
	KnownGood []string `json:"known_good"`
}
type child struct {
	cmd        *exec.Cmd
	done       chan struct{}
	generation uint64
	monitor    bool
	arm        chan struct{}
	armOnce    sync.Once
}
type Supervisor struct {
	opts            Options
	dir             string
	lock            *os.File
	op              sync.Mutex
	mu              sync.Mutex
	gate            sync.Mutex
	j               journal
	child           *child
	status          Status
	events          []Event
	generation      uint64
	desired, closed bool
	ctx             context.Context
	cancel          context.CancelFunc
	crashes         []time.Time
}

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(opts Options) (*Supervisor, error) {
	if opts.Directory == "" {
		return nil, errors.New("supervisor directory required")
	}
	if opts.Semantic == nil || opts.Hooks.Quarantine == nil || opts.Hooks.Prepare == nil || opts.Hooks.Probe == nil || opts.Hooks.Release == nil {
		return nil, errors.New("supervisor requires semantic validation and lifecycle hooks")
	}
	if opts.KeepRevisions == 0 {
		opts.KeepRevisions = 5
	}
	if opts.KeepRevisions < 1 || opts.KeepRevisions > 5 {
		return nil, errors.New("invalid revision retention")
	}
	if opts.StopTimeout == 0 {
		opts.StopTimeout = 3 * time.Second
	}
	if opts.ReadyTimeout == 0 {
		opts.ReadyTimeout = 10 * time.Second
	}
	if opts.BackoffInitial == 0 {
		opts.BackoffInitial = 100 * time.Millisecond
	}
	if opts.BackoffMax == 0 {
		opts.BackoffMax = 5 * time.Second
	}
	if opts.CrashLimit == 0 {
		opts.CrashLimit = 5
	}
	if opts.CrashWindow == 0 {
		opts.CrashWindow = time.Minute
	}
	if opts.StopTimeout <= 0 || opts.ReadyTimeout <= 0 || opts.BackoffInitial <= 0 || opts.BackoffMax < opts.BackoffInitial || opts.CrashLimit < 1 || opts.CrashWindow <= 0 {
		return nil, errors.New("invalid supervisor limits")
	}
	binary, err := filepath.Abs(opts.Binary)
	if err != nil {
		return nil, errors.New("invalid core executable")
	}
	st, err := os.Stat(binary)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return nil, errors.New("core executable unavailable")
	}
	opts.Binary = binary
	dir, err := filepath.Abs(opts.Directory)
	if err != nil || parents(dir) != nil {
		return nil, errors.New("unsafe supervisor directory")
	}
	if os.MkdirAll(dir, 0700) != nil {
		return nil, errors.New("supervisor directory unavailable")
	}
	st, err = os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("supervisor directory must be private")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "supervisor.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("supervisor lock unavailable")
	}
	st, err = lock.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("supervisor already owned or lock invalid")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Supervisor{opts: opts, dir: dir, lock: lock, j: journal{Schema: 1, KnownGood: []string{}}, ctx: ctx, cancel: cancel, status: Status{State: "stopped"}}
	if err = s.load(); err != nil {
		s.unlock()
		cancel()
		return nil, err
	}
	if s.j.PID != 0 {
		if syscall.Kill(s.j.PID, 0) != syscall.ESRCH {
			s.unlock()
			cancel()
			return nil, errors.New("recorded process ownership is ambiguous; refusing reopen")
		}
		s.j.PID = 0
		if err = s.persist(); err != nil {
			s.unlock()
			cancel()
			return nil, err
		}
	}
	s.status.Revision = s.j.Active
	if opts.Validator == nil {
		s.opts.Validator = func(ctx context.Context, path string) error { return singbox.Check(ctx, s.opts.Binary, path) }
	}
	return s, nil
}
func (s *Supervisor) Status() Status { s.mu.Lock(); defer s.mu.Unlock(); return s.status }

// RetainedRevisions includes every durable LKG and pending recovery revision.
// Call outside lifecycle hooks: it serializes with apply/stop journal mutations.
func (s *Supervisor) RetainedRevisions() []string {
	s.op.Lock()
	defer s.op.Unlock()
	out := append([]string{}, s.j.KnownGood...)
	seen := map[string]bool{}
	for _, hash := range out {
		seen[hash] = true
	}
	for _, hash := range []string{s.j.Active, s.j.Pending} {
		if hash != "" && !seen[hash] {
			out = append(out, hash)
			seen[hash] = true
		}
	}
	return out
}
func (s *Supervisor) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}
func (s *Supervisor) event(code, revision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, Event{time.Now().UTC(), code, revision})
	if len(s.events) > 128 {
		s.events = s.events[len(s.events)-128:]
	}
}
func (s *Supervisor) fail(code string) error {
	s.mu.Lock()
	s.status.LastError = code
	s.mu.Unlock()
	s.event(code, "")
	return errors.New(code)
}
func (s *Supervisor) quarantine(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, s.opts.ReadyTimeout)
	defer cancel()
	ctx = bounded
	s.gate.Lock()
	defer s.gate.Unlock()
	s.mu.Lock()
	s.status.Ready = false
	s.status.State = "quarantined"
	s.mu.Unlock()
	if s.opts.Hooks.Quarantine(ctx) != nil {
		return errors.New("quarantine failed")
	}
	s.event("quarantined", "")
	return nil
}
func (s *Supervisor) Apply(ctx context.Context, data []byte) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed {
		return s.fail("supervisor closed")
	}
	if s.j.Pending != "" {
		return s.fail("pending revision requires recovery")
	}
	if len(data) == 0 || len(data) > 4<<20 {
		return s.fail("candidate size invalid")
	}
	if s.opts.Semantic(data) != nil {
		return s.fail("candidate semantic validation failed")
	}
	h := sha256.Sum256(data)
	revision := hex.EncodeToString(h[:])
	path, err := s.revision(revision, data)
	if err != nil {
		return s.fail("candidate persistence failed")
	}
	defer s.prune()
	if s.validate(ctx, path) != nil {
		return s.fail("candidate core validation failed")
	}
	s.event("candidate-validated", revision)
	oldJournal := s.j
	oldJournal.KnownGood = append([]string(nil), s.j.KnownGood...)
	old := s.j.Active
	s.j.Pending = revision
	if s.persist() != nil {
		return s.fail("pending persistence failed")
	}
	if s.quarantine(ctx) != nil {
		recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), s.opts.ReadyTimeout)
		_ = s.quarantine(recoveryCtx)
		recoveryCancel()
		s.stopChild()
		s.j.PID = 0
		_ = s.persist()
		return s.fail("quarantine failed")
	}
	s.stopChild()
	s.j.PID = 0
	if err = s.launch(ctx, revision, true); err == nil {
		return nil
	}
	s.event("candidate-rejected", revision)
	recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), s.opts.ReadyTimeout)
	defer recoveryCancel()
	quarantineErr := s.quarantine(recoveryCtx)
	s.stopChild()
	s.j.PID = 0
	s.j.Active = old
	s.j.KnownGood = oldJournal.KnownGood
	s.j.Pending = revision
	if old == "" {
		s.j.Pending = ""
	}
	if s.persist() != nil {
		return s.fail("rollback persistence failed")
	}
	if quarantineErr != nil {
		return s.fail("rollback quarantine failed")
	}
	if old != "" {
		if s.launch(recoveryCtx, old, false) != nil {
			_ = s.quarantine(recoveryCtx)
			s.stopChild()
			s.j.PID = 0
			s.j.Pending = revision
			_ = s.persist()
			return s.fail("last-known-good recovery failed")
		}
		s.event("rolled-back", old)
	}
	return s.fail("candidate activation failed")
}
func (s *Supervisor) Start(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed {
		return s.fail("supervisor closed")
	}
	s.mu.Lock()
	hasChild := s.child != nil
	s.mu.Unlock()
	if hasChild {
		return s.fail("core already running")
	}
	if s.j.Active == "" {
		return s.fail("no last-known-good revision")
	}
	data, err := readPrivate(s.path(s.j.Active), 4<<20)
	if err != nil || s.opts.Semantic(data) != nil || s.validate(ctx, s.path(s.j.Active)) != nil {
		return s.fail("last-known-good validation failed")
	}
	if s.quarantine(ctx) != nil {
		return s.fail("quarantine failed")
	}
	s.j.PID = 0
	if s.persist() != nil {
		return s.fail("recovery persistence failed")
	}
	pending := s.j.Pending
	if s.launch(ctx, s.j.Active, false) != nil {
		_ = s.quarantine(context.Background())
		s.stopChild()
		s.j.Pending = pending
		s.j.PID = 0
		_ = s.persist()
		return s.fail("last-known-good start failed")
	}
	return nil
}
func (s *Supervisor) Stop(ctx context.Context) error {
	s.op.Lock()
	defer s.op.Unlock()
	if s.closed {
		return nil
	}
	err := s.quarantine(ctx)
	s.stopChild()
	s.j.PID = 0
	if s.persist() != nil {
		return s.fail("stop persistence failed")
	}
	s.mu.Lock()
	s.status.State = "stopped"
	s.mu.Unlock()
	s.event("stopped", s.j.Active)
	if err != nil {
		return s.fail("quarantine failed")
	}
	return nil
}
func (s *Supervisor) Close(ctx context.Context) error {
	err := s.Stop(ctx)
	s.op.Lock()
	defer s.op.Unlock()
	if !s.closed {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.cancel()
		s.unlock()
	}
	return err
}
func (s *Supervisor) launch(ctx context.Context, revision string, candidate bool) error {
	path := s.path(revision)
	data, err := readPrivate(path, 4<<20)
	if err != nil {
		return errors.New("revision unavailable")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != revision || s.opts.Semantic(data) != nil {
		return errors.New("revision validation failed")
	}
	if !candidate && s.validate(ctx, path) != nil {
		return errors.New("core revision validation failed")
	}
	ready, cancel := context.WithTimeout(ctx, s.opts.ReadyTimeout)
	defer cancel()
	if s.opts.Hooks.Prepare(ready, path) != nil {
		return errors.New("prepare failed")
	}
	cmd := exec.Command(s.opts.Binary, "run", "-c", path)
	cmd.Dir = s.dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	processAttributes(cmd)
	if cmd.Start() != nil {
		return errors.New("core start failed")
	}
	s.mu.Lock()
	s.generation++
	c := &child{cmd: cmd, done: make(chan struct{}), arm: make(chan struct{}), generation: s.generation}
	s.child = c
	s.desired = true
	s.status.Live = true
	s.status.Ready = false
	s.status.PID = cmd.Process.Pid
	s.status.State = "starting"
	s.mu.Unlock()
	go func() { _ = cmd.Wait(); close(c.done); <-c.arm; s.exited(c) }()
	s.j.PID = cmd.Process.Pid
	if s.persist() != nil {
		return errors.New("process journal persistence failed")
	}
	s.event("started", revision)
	if s.opts.Hooks.Probe(ready, path) != nil {
		return errors.New("core readiness failed")
	}
	select {
	case <-c.done:
		return errors.New("core exited during readiness")
	default:
	}
	if ready.Err() != nil {
		return errors.New("core readiness timeout")
	}
	if candidate {
		s.j.Active = revision
		s.j.Pending = ""
		known := []string{revision}
		for _, v := range s.j.KnownGood {
			if v != revision && len(known) < s.opts.KeepRevisions {
				known = append(known, v)
			}
		}
		s.j.KnownGood = known
	}
	s.j.Pending = ""
	if s.persist() != nil {
		return errors.New("active persistence failed")
	}
	s.gate.Lock()
	err = s.opts.Hooks.Release(ready)
	s.gate.Unlock()
	if err != nil {
		return errors.New("traffic release failed")
	}
	select {
	case <-c.done:
		return errors.New("core exited during release")
	default:
	}
	s.mu.Lock()
	c.monitor = true
	s.status.Ready = true
	s.status.Revision = revision
	s.status.State = "ready"
	s.status.LastError = ""
	s.mu.Unlock()
	c.armOnce.Do(func() { close(c.arm) })
	s.event("ready", revision)
	s.prune()
	return nil
}
func (s *Supervisor) stopChild() {
	s.mu.Lock()
	s.generation++
	s.desired = false
	c := s.child
	s.child = nil
	s.status.Live = false
	s.status.Ready = false
	s.status.PID = 0
	s.mu.Unlock()
	if c == nil {
		return
	}
	c.armOnce.Do(func() { close(c.arm) })
	_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(s.opts.StopTimeout)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
		_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		<-c.done
	}
}
func (s *Supervisor) exited(c *child) {
	s.mu.Lock()
	if s.child != c || s.generation != c.generation || !s.desired || !c.monitor {
		s.mu.Unlock()
		return
	}
	s.status.Ready = false
	s.status.Live = false
	s.status.PID = 0
	s.status.State = "quarantined"
	s.mu.Unlock()
	qctx, cancel := context.WithTimeout(s.ctx, s.opts.ReadyTimeout)
	current, qerr := s.quarantineCurrent(qctx, c)
	cancel()
	if !current {
		return
	}
	s.event("core-exited", "")
	s.op.Lock()
	if !s.current(c) {
		s.op.Unlock()
		return
	}
	s.mu.Lock()
	s.child = nil
	s.mu.Unlock()
	s.j.PID = 0
	if s.persist() != nil || qerr != nil {
		s.mu.Lock()
		s.desired = false
		s.mu.Unlock()
		s.op.Unlock()
		s.fail("crash recovery blocked")
		return
	}
	generation := c.generation
	s.op.Unlock()
	delay := s.opts.BackoffInitial
	for {
		now := time.Now()
		s.op.Lock()
		s.mu.Lock()
		valid := !s.closed && s.desired && s.generation == generation
		s.mu.Unlock()
		if !valid {
			s.op.Unlock()
			return
		}
		fresh := s.crashes[:0]
		for _, v := range s.crashes {
			if now.Sub(v) < s.opts.CrashWindow {
				fresh = append(fresh, v)
			}
		}
		s.crashes = append(fresh, now)
		delay = s.opts.BackoffInitial
		for i := 1; i < len(s.crashes) && delay < s.opts.BackoffMax; i++ {
			delay *= 2
		}
		if delay > s.opts.BackoffMax {
			delay = s.opts.BackoffMax
		}
		if len(s.crashes) >= s.opts.CrashLimit {
			s.mu.Lock()
			s.desired = false
			s.status.State = "crash-loop"
			s.status.LastError = "crash loop"
			s.mu.Unlock()
			s.event("crash-loop", s.j.Active)
			s.op.Unlock()
			return
		}
		s.mu.Lock()
		s.status.State = "backoff"
		s.mu.Unlock()
		s.op.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-s.ctx.Done():
			timer.Stop()
			return
		}
		s.op.Lock()
		s.mu.Lock()
		valid = !s.closed && s.desired && s.generation == generation
		s.mu.Unlock()
		if !valid {
			s.op.Unlock()
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.opts.ReadyTimeout)
		err := s.launch(ctx, s.j.Active, false)
		cancel()
		if err == nil {
			s.mu.Lock()
			s.status.Restarts++
			s.mu.Unlock()
			s.event("restarted", s.j.Active)
			s.op.Unlock()
			return
		}
		recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), s.opts.ReadyTimeout)
		_ = s.quarantine(recoveryCtx)
		recoveryCancel()
		s.stopChild()
		s.j.PID = 0
		_ = s.persist()
		s.mu.Lock()
		s.desired = true
		generation = s.generation
		s.mu.Unlock()
		s.op.Unlock()
		if delay < s.opts.BackoffMax {
			delay *= 2
			if delay > s.opts.BackoffMax {
				delay = s.opts.BackoffMax
			}
		}
	}
}
func (s *Supervisor) current(c *child) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.child == c && s.generation == c.generation && s.desired
}
func (s *Supervisor) path(revision string) string { return filepath.Join(s.dir, revision+".json") }
func (s *Supervisor) revision(hash string, data []byte) (string, error) {
	path := s.path(hash)
	if b, err := readPrivate(path, 4<<20); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != hash {
			return "", errors.New("revision hash mismatch")
		}
		return path, nil
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return "", errors.New("unsafe revision")
	}
	if err := atomicPrivate(s.dir, path, data); err != nil {
		return "", err
	}
	return path, nil
}
func (s *Supervisor) persist() error {
	b, err := json.Marshal(s.j)
	if err != nil {
		return err
	}
	return atomicPrivate(s.dir, filepath.Join(s.dir, "journal.json"), b)
}
func (s *Supervisor) load() error {
	b, err := readPrivate(filepath.Join(s.dir, "journal.json"), 64<<10)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("invalid supervisor journal")
	}
	if strictJSON(b) != nil {
		return errors.New("invalid supervisor journal")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&s.j) != nil || s.j.Schema != 1 || s.j.PID < 0 || s.j.PID > 2147483647 || len(s.j.KnownGood) > 5 {
		return errors.New("invalid supervisor journal")
	}
	unique := map[string]bool{}
	for _, hash := range s.j.KnownGood {
		if unique[hash] {
			return errors.New("duplicate last-known-good revision")
		}
		unique[hash] = true
	}
	refs := append([]string{}, s.j.KnownGood...)
	if s.j.Active != "" {
		refs = append(refs, s.j.Active)
	}
	if s.j.Pending != "" {
		refs = append(refs, s.j.Pending)
	}
	for _, hash := range refs {
		if !hashPattern.MatchString(hash) {
			return errors.New("invalid supervisor revision")
		}
		data, err := readPrivate(s.path(hash), 4<<20)
		if err != nil {
			return errors.New("revision unavailable")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			return errors.New("revision integrity failed")
		}
	}
	if s.j.Active != "" {
		found := false
		for _, v := range s.j.KnownGood {
			if v == s.j.Active {
				found = true
			}
		}
		if !found {
			return errors.New("active revision is not last-known-good")
		}
	}
	return nil
}
func (s *Supervisor) prune() {
	files, _ := os.ReadDir(s.dir)
	keep := map[string]bool{}
	for _, v := range s.j.KnownGood {
		keep[v] = true
	}
	keep[s.j.Active] = true
	keep[s.j.Pending] = true
	for _, f := range files {
		hash := strings.TrimSuffix(f.Name(), ".json")
		if hashPattern.MatchString(hash) && !keep[hash] {
			_ = os.Remove(filepath.Join(s.dir, f.Name()))
		}
	}
}
func (s *Supervisor) unlock() {
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
		s.lock = nil
	}
}
func parents(path string) error {
	for {
		st, err := os.Lstat(path)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink path")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		p := filepath.Dir(path)
		if p == path {
			return nil
		}
		path = p
	}
}
func readPrivate(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > max {
		return nil, errors.New("invalid private file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("private file bound")
	}
	return b, nil
}
func atomicPrivate(dir, path string, b []byte) error {
	if parents(dir) != nil {
		return errors.New("unsafe state directory")
	}
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return errors.New("invalid private target")
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err == nil {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		d.Close()
		return err
	}
	return err
}
func strictJSON(b []byte) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return errors.New("duplicate JSON key")
				}
				keys[key] = true
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON")
		}
		_, err = d.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (s *Supervisor) validate(ctx context.Context, path string) error {
	bounded, cancel := context.WithTimeout(ctx, s.opts.ReadyTimeout)
	defer cancel()
	return s.opts.Validator(bounded, path)
}
func (s *Supervisor) quarantineCurrent(ctx context.Context, c *child) (bool, error) {
	s.gate.Lock()
	defer s.gate.Unlock()
	if !s.current(c) {
		return false, nil
	}
	s.mu.Lock()
	s.status.Ready = false
	s.status.State = "quarantined"
	s.mu.Unlock()
	if s.opts.Hooks.Quarantine(ctx) != nil {
		return true, errors.New("quarantine failed")
	}
	s.event("quarantined", "")
	return true, nil
}
