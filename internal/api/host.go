package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/namespace"
)

// CoreOwner is implemented by the accepted single-writer Transition. Test owners
// are trusted seams; there is no HTTP facility to supply hooks or kernel paths.
type CoreOwner interface {
	Status() coreactivation.TransitionStatus
	CurrentModel() (coreconfig.Model, error)
	ValidateModel(context.Context, uint64, coreconfig.Model) error
	Apply(context.Context, uint64, []string, coreconfig.Model) (namespace.Snapshot, error)
	Recover(context.Context) (namespace.Snapshot, error)
	Hold(context.Context) error
	Check(context.Context) error
	Close(context.Context) error
}
type HostOptions struct {
	Core              CoreOwner
	Reconcile         func(context.Context) error
	Probe             func(context.Context) error
	Interval, Timeout time.Duration
}
type Host struct {
	history    history
	closeDone  chan struct{}
	closeError error
	op         sync.Mutex
	o          HostOptions
	ready      atomic.Bool
	closed     atomic.Bool
	life       context.Context
	cancel     context.CancelFunc
	running    atomic.Bool
	done       chan struct{}
}

func NewHost(o HostOptions) (*Host, error) {
	if o.Core == nil || o.Reconcile == nil || o.Probe == nil {
		return nil, errors.New("verified core, ledger reconcile and active canary required")
	}
	if o.Interval == 0 {
		o.Interval = 2 * time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Interval < time.Second || o.Interval > time.Minute || o.Timeout < time.Second || o.Timeout > time.Minute {
		return nil, errors.New("invalid runtime bounds")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Host{o: o, life: ctx, cancel: cancel, done: make(chan struct{}), closeDone: make(chan struct{})}, nil
}
func (h *Host) bounded(ctx context.Context) (context.Context, func()) {
	c, cancel := context.WithTimeout(ctx, h.o.Timeout)
	stop := context.AfterFunc(h.life, cancel)
	return c, func() { stop(); cancel() }
}
func (h *Host) View() RuntimeView {
	s := h.o.Core.Status()
	return RuntimeView{s.Namespace.Revision, !h.closed.Load() && h.ready.Load() && s.Ready, s.Namespace.Pending != nil}
}
func (h *Host) Model() (coreconfig.Model, error) {
	if h.closed.Load() {
		return coreconfig.Model{}, errors.New("runtime closed")
	}
	return h.o.Core.CurrentModel()
}
func (h *Host) Validate(ctx context.Context, rev uint64, m coreconfig.Model) error {
	h.op.Lock()
	defer h.op.Unlock()
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	c, done := h.bounded(ctx)
	defer done()
	return h.o.Core.ValidateModel(c, rev, m)
}
func (h *Host) hold() error {
	wasReady := h.ready.Swap(false)
	if wasReady {
		h.history.record("readiness_withdrawn", false, h.View().Revision)
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.o.Timeout)
	defer cancel()
	return h.o.Core.Hold(ctx)
}
func (h *Host) verify(ctx context.Context) error {
	if e := h.o.Reconcile(ctx); e != nil {
		h.history.record("mapping_reconcile_failed", false, h.View().Revision)
		return e
	}
	if e := h.o.Core.Check(ctx); e != nil {
		h.history.record("core_check_failed", false, h.View().Revision)
		return e
	}
	if e := h.o.Probe(ctx); e != nil {
		h.history.record("canary_failed", false, h.View().Revision)
		return errors.New("current canary failed")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if !h.o.Core.Status().Ready {
		return errors.New("core admission not ready")
	}
	return nil
}
func (h *Host) Apply(ctx context.Context, rev uint64, m coreconfig.Model) error {
	return h.apply(ctx, rev, m, "")
}
func (h *Host) ApplyPrepared(ctx context.Context, rev uint64, m coreconfig.Model, fp string) error {
	if len(fp) != 64 {
		return coreactivation.ErrCandidateChanged
	}
	return h.apply(ctx, rev, m, fp)
}
func (h *Host) apply(ctx context.Context, rev uint64, m coreconfig.Model, fp string) error {
	h.op.Lock()
	defer h.op.Unlock()
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	c, done := h.bounded(ctx)
	defer done()
	// Preflight before withdrawing host readiness, just as the core owner requires.
	if e := h.o.Core.ValidateModel(c, rev, m); e != nil {
		return e
	}
	wasReady := h.View().Ready
	h.ready.Store(false)
	h.history.record("apply_started", false, h.View().Revision)
	var applyErr error
	if fp != "" {
		if owner, ok := h.o.Core.(interface {
			ApplyPrepared(context.Context, uint64, []string, coreconfig.Model, string) (namespace.Snapshot, error)
		}); ok {
			_, applyErr = owner.ApplyPrepared(c, rev, m.DNS.SelectedDomains, m, fp)
		} else {
			expected, e := modelFingerprint(m)
			if e != nil || fp != expected || len(m.RuleSets) > 0 {
				applyErr = coreactivation.ErrCandidateChanged
			} else {
				_, applyErr = h.o.Core.Apply(c, rev, m.DNS.SelectedDomains, m)
			}
		}
	} else {
		_, applyErr = h.o.Core.Apply(c, rev, m.DNS.SelectedDomains, m)
	}
	if applyErr != nil {
		if errors.Is(applyErr, coreactivation.ErrCandidateChanged) && wasReady && h.o.Core.Status().Ready {
			h.ready.Store(true)
			return applyErr
		}
		h.history.record("apply_failed", false, h.View().Revision)
		return errors.Join(errors.New("runtime apply failed"), applyErr, h.hold())
	}
	if e := h.verify(c); e != nil {
		return errors.Join(e, h.hold())
	}
	h.ready.Store(true)
	h.history.record("apply_verified", true, h.View().Revision)
	return nil
}
func (h *Host) Recover(ctx context.Context) error {
	h.op.Lock()
	defer h.op.Unlock()
	return h.recover(ctx)
}
func (h *Host) recover(ctx context.Context) error {
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	h.ready.Store(false)
	h.history.record("recovery_started", false, h.View().Revision)
	c, done := h.bounded(ctx)
	defer done()
	if _, e := h.o.Core.Recover(c); e != nil {
		h.history.record("recovery_failed", false, h.View().Revision)
		return errors.Join(errors.New("runtime recovery failed"), h.hold())
	}
	if e := h.verify(c); e != nil {
		return errors.Join(e, h.hold())
	}
	h.ready.Store(true)
	h.history.record("recovery_verified", true, h.View().Revision)
	return nil
}
func (h *Host) Tick(ctx context.Context) error {
	h.op.Lock()
	defer h.op.Unlock()
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	if !h.ready.Load() {
		return h.recover(ctx)
	}
	c, done := h.bounded(ctx)
	defer done()
	if e := h.verify(c); e != nil {
		return errors.Join(e, h.hold())
	}
	return nil
}

// Run owns periodic checking, closes on cancellation, and permits one runner.
// Bind DNS and the separate private readiness listener before Run: quarantine
// must be observable by the native watchdog while startup/recovery is pending.
func (h *Host) Run(ctx context.Context) error {
	if !h.running.CompareAndSwap(false, true) {
		return errors.New("runtime already running")
	}
	defer close(h.done)
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	h.op.Lock()
	e := h.hold()
	h.op.Unlock()
	if e != nil {
		return errors.Join(e, h.Close(context.Background()))
	}
	_ = h.Recover(ctx)
	tick := time.NewTicker(h.o.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return h.Close(context.Background())
		case <-h.life.Done():
			return h.Close(context.Background())
		case <-tick.C:
			_ = h.Tick(ctx)
		}
	}
}
func (h *Host) Close(ctx context.Context) error {
	if !h.closed.CompareAndSwap(false, true) {
		select {
		case <-h.closeDone:
			return h.closeError
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer close(h.closeDone)
	h.ready.Store(false)
	h.history.record("runtime_stopped", false, h.View().Revision)
	h.cancel()
	h.op.Lock()
	defer h.op.Unlock()
	c, cancel := context.WithTimeout(ctx, h.o.Timeout)
	defer cancel()
	h.closeError = h.o.Core.Close(c)
	return h.closeError
}

// ReadinessHandler exposes only a boolean to a private native observer. The
// deployment owner must restrict the listener; it is separate from admin auth.
func (h *Host) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/" || r.URL.RawQuery != "" {
			reject(w, 404, "not_found")
			return
		}
		ready := h.View().Ready
		code := 503
		if ready {
			code = 200
		}
		w.Header().Set("Cache-Control", "no-store")
		reply(w, code, map[string]bool{"ready": ready})
	})
}

func (h *Host) Done() <-chan struct{} { return h.done }

var _ Runtime = (*Host)(nil)
var _ CoreOwner = (*coreactivation.Transition)(nil)

func modelFingerprint(m coreconfig.Model) (string, error) {
	if len(m.RuleSets) > 0 {
		return "", errors.New("resolved artifact fingerprint required")
	}
	b, e := json.Marshal(m)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func (h *Host) CandidateFingerprint(ctx context.Context, rev uint64, m coreconfig.Model) (string, error) {
	h.op.Lock()
	defer h.op.Unlock()
	if h.closed.Load() {
		return "", errors.New("runtime closed")
	}
	c, done := h.bounded(ctx)
	defer done()
	if owner, ok := h.o.Core.(interface {
		CandidateFingerprint(context.Context, uint64, coreconfig.Model) (string, error)
	}); ok {
		return owner.CandidateFingerprint(c, rev, m)
	}
	if e := c.Err(); e != nil {
		return "", e
	}
	return modelFingerprint(m)
}

var _ PreparedRuntime = (*Host)(nil)

// Inspect serializes a bounded read-only diagnostic with policy transitions and
// the health owner. It never changes readiness or authorizes arbitrary hooks via
// HTTP; only the trusted application composition supplies this function.
func (h *Host) Inspect(ctx context.Context, probe func(context.Context) error) error {
	h.op.Lock()
	defer h.op.Unlock()
	if h.closed.Load() {
		return errors.New("runtime closed")
	}
	c, done := h.bounded(ctx)
	defer done()
	return probe(c)
}
