package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/namespace"
)

type hostOwner struct {
	mu        sync.Mutex
	m         coreconfig.Model
	s         coreactivation.TransitionStatus
	events    []string
	failApply bool
	closes    int
}

func (o *hostOwner) event(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, name)
}
func (o *hostOwner) Status() coreactivation.TransitionStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.s
}
func (o *hostOwner) CurrentModel() (coreconfig.Model, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.m.Clone()
}
func (o *hostOwner) ValidateModel(ctx context.Context, rev uint64, m coreconfig.Model) error {
	o.event("validate")
	if rev != o.Status().Namespace.Revision {
		return errors.New("stale")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return m.Validate()
}
func (o *hostOwner) Apply(ctx context.Context, rev uint64, active []string, m coreconfig.Model) (namespace.Snapshot, error) {
	o.event("apply")
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failApply {
		o.s.Ready = false
		o.s.Namespace.Pending = &namespace.Pending{Revision: rev + 1, Active: active}
		return o.s.Namespace, errors.New("failed")
	}
	o.m = m
	o.s.Namespace.Revision++
	o.s.Namespace.Active = active
	o.s.Ready = true
	return o.s.Namespace, ctx.Err()
}
func (o *hostOwner) Recover(ctx context.Context) (namespace.Snapshot, error) {
	o.event("recover")
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.s.Namespace.Pending != nil {
		o.s.Namespace.Revision = o.s.Namespace.Pending.Revision
		o.s.Namespace.Active = o.s.Namespace.Pending.Active
		o.s.Namespace.Pending = nil
	}
	o.s.Ready = true
	return o.s.Namespace, ctx.Err()
}
func (o *hostOwner) Hold(ctx context.Context) error {
	o.event("hold")
	o.mu.Lock()
	defer o.mu.Unlock()
	o.s.Ready = false
	return ctx.Err()
}
func (o *hostOwner) Check(ctx context.Context) error { o.event("check"); return ctx.Err() }
func (o *hostOwner) Close(ctx context.Context) error {
	o.event("close")
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closes++
	o.s.Ready = false
	return ctx.Err()
}
func newTestHost(t *testing.T) (*Host, *hostOwner, *atomic.Bool) {
	t.Helper()
	o := &hostOwner{m: fixture(t), s: coreactivation.TransitionStatus{Namespace: namespace.Snapshot{Revision: 1}}}
	fail := new(atomic.Bool)
	h, e := NewHost(HostOptions{Core: o, Reconcile: func(ctx context.Context) error { o.event("reconcile"); return ctx.Err() }, Probe: func(ctx context.Context) error {
		o.event("probe")
		if fail.Load() {
			return errors.New("bad active path")
		}
		return ctx.Err()
	}, Interval: time.Second, Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close(context.Background()) })
	return h, o, fail
}
func TestHostRequiresCurrentProofAfterRecoverAndApply(t *testing.T) {
	h, o, fail := newTestHost(t)
	if h.View().Ready {
		t.Fatal("disk-only ready")
	}
	if e := h.Recover(context.Background()); e != nil || !h.View().Ready {
		t.Fatal(e)
	}
	o.mu.Lock()
	events := append([]string(nil), o.events...)
	o.mu.Unlock()
	if len(events) != 4 || events[0] != "recover" || events[1] != "reconcile" || events[2] != "check" || events[3] != "probe" {
		t.Fatal(events)
	}
	fail.Store(true)
	if h.Apply(context.Background(), 1, fixture(t)) == nil || h.View().Ready {
		t.Fatal("canary failed after apply but host ready")
	}
	if o.Status().Ready {
		t.Fatal("child not held")
	}
	fail.Store(false)
	if e := h.Tick(context.Background()); e != nil || !h.View().Ready {
		t.Fatal("fresh recovery", e)
	}
	if h.Apply(context.Background(), 1, fixture(t)) == nil || !h.View().Ready {
		t.Fatal("stale preflight disturbed healthy core")
	}
}
func TestHostFailureRecoversForwardAndReadinessIsBoolean(t *testing.T) {
	h, o, _ := newTestHost(t)
	h.Recover(context.Background())
	o.failApply = true
	if h.Apply(context.Background(), 1, fixture(t)) == nil || !h.View().Pending || h.View().Ready {
		t.Fatal("pending admission")
	}
	w := httptest.NewRecorder()
	h.ReadinessHandler().ServeHTTP(w, httptest.NewRequest("GET", "http://172.30.0.2/", nil))
	if w.Code != 503 || w.Body.String() != "{\"ready\":false}\n" {
		t.Fatal(w.Body.String())
	}
	o.failApply = false
	if e := h.Recover(context.Background()); e != nil || h.View().Pending || !h.View().Ready || h.View().Revision != 2 {
		t.Fatal(e)
	}
	h.Close(context.Background())
	h.Close(context.Background())
	if o.closes != 1 || h.View().Ready {
		t.Fatal("shutdown repeated or ready")
	}
}
func TestHostRunCancellationStopsOwner(t *testing.T) {
	h, o, _ := newTestHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- h.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !h.View().Ready && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !h.View().Ready {
		t.Fatal("startup did not prove readiness")
	}
	cancel()
	select {
	case e := <-finished:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hung")
	}
	if h.View().Ready || o.closes != 1 {
		t.Fatal("owned core leaked")
	}
	if h.Run(context.Background()) == nil {
		t.Fatal("duplicate run")
	}
}

func TestChangedPreparedModelCannotGrantInitialHostReadiness(t *testing.T) {
	h, o, _ := newTestHost(t)
	o.mu.Lock()
	o.s.Ready = true
	o.mu.Unlock()
	if h.ApplyPrepared(context.Background(), 1, fixture(t), "invalid") == nil || h.View().Ready {
		t.Fatal("unproved host became ready")
	}
	wrong := strings.Repeat("0", 64)
	if h.ApplyPrepared(context.Background(), 1, fixture(t), wrong) == nil || h.View().Ready {
		t.Fatal("stale plan granted readiness")
	}
}
