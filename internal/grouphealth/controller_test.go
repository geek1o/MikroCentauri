package grouphealth

import (
	"context"
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) coreconfig.Model {
	t.Helper()
	a, e := endpoints.ParseURI("ss://aes-256-gcm:first-secret@127.0.0.1:12345#first")
	if e != nil {
		t.Fatal(e)
	}
	b, e := endpoints.ParseURI("ss://aes-256-gcm:second-secret@127.0.0.1:12346#second")
	if e != nil {
		t.Fatal(e)
	}
	return coreconfig.Model{SchemaVersion: 2, Instance: "health", Mode: "socksify", Endpoints: []endpoints.Endpoint{a, b}, Groups: []coreconfig.Group{{ID: "fallback", Type: "fallback", Members: []string{a.ID, b.ID}, Selected: b.ID}}, DefaultOutbound: "fallback", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/health/cache.db"}}
}
func healthy(ep endpoints.Endpoint) Observation {
	now := time.Now().UTC()
	return Observation{EndpointID: ep.ID, CheckedAt: now, Health: coreconfig.Health{Available: true, LastSuccess: now, Latency: time.Millisecond}}
}
func TestFallbackPriorityFailureRecovery(t *testing.T) {
	m := fixture(t)
	var apply, q atomic.Int32
	failed := false
	badApply := false
	o := Options{Model: m, GroupID: "fallback", Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) {
		if failed {
			return Observation{}, errors.New("secret-probe")
		}
		v := healthy(ep)
		if ep.ID == m.Endpoints[0].ID {
			v.Latency = time.Second
		}
		return v, nil
	}, ApplyModel: func(context.Context, coreconfig.Model) error {
		apply.Add(1)
		if badApply {
			return errors.New("secret-apply")
		}
		return nil
	}, Quarantine: func(context.Context) error { q.Add(1); return nil }}
	c, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Tick(context.Background()); e != nil || c.Status().Selected != m.Endpoints[0].ID || !(!c.Status().Quarantined) {
		t.Fatal("not priority ordered", e)
	}
	if e = c.Tick(context.Background()); e != nil || apply.Load() != 1 {
		t.Fatal("unchanged healthy selection reapplied")
	}
	failed = true
	if e = c.Tick(context.Background()); e == nil || q.Load() != 1 || !c.Status().Quarantined || c.Status().Selected != m.Endpoints[0].ID {
		t.Fatal("unhealthy did not quarantine")
	}
	observed := c.Observations()[m.Endpoints[0].ID]
	if observed.LastSuccess.IsZero() || observed.LastFailure.IsZero() || observed.Available {
		t.Fatal("observation history")
	}
	failed = false
	badApply = true
	if e = c.Tick(context.Background()); e == nil || c.Status().Selected != m.Endpoints[0].ID || !c.Status().Quarantined {
		t.Fatal("failed apply selected")
	}
	badApply = false
	if e = c.Tick(context.Background()); e != nil || c.Status().Quarantined {
		t.Fatal("did not release recovery", e)
	}
}
func TestCancelSupersededTick(t *testing.T) {
	m := fixture(t)
	entered := make(chan struct{})
	var once atomic.Bool
	var apply atomic.Int32
	c, e := New(Options{Model: m, GroupID: "fallback", Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) {
		if once.CompareAndSwap(false, true) {
			close(entered)
			<-ctx.Done()
			return Observation{}, ctx.Err()
		}
		return healthy(ep), nil
	}, ApplyModel: func(context.Context, coreconfig.Model) error { apply.Add(1); return nil }, Quarantine: func(context.Context) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error)
	go func() { done <- c.Tick(context.Background()) }()
	<-entered
	if e = c.UpdateModel(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil || apply.Load() != 0 || c.Status().State != "unobserved" {
		t.Fatal("stale tick applied")
	}
	old := c.Status().Selected
	if old != m.Groups[0].Selected {
		t.Fatal("unobserved model changed active selection")
	}
	if e = c.Tick(context.Background()); e != nil || apply.Load() != 1 || c.Status().Selected != m.Endpoints[0].ID {
		t.Fatal("fresh observation did not precede apply", e)
	}
}
func TestFreshnessAndMandatoryCallbacks(t *testing.T) {
	m := fixture(t)
	if _, e := New(Options{Model: m, GroupID: "fallback"}); e == nil {
		t.Fatal("missing hooks")
	}
	c, e := New(Options{Model: m, GroupID: "fallback", Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) {
		o := healthy(ep)
		o.LastSuccess = time.Now().Add(-time.Hour)
		return o, nil
	}, ApplyModel: func(context.Context, coreconfig.Model) error { t.Fatal("stale health activated"); return nil }, Quarantine: func(context.Context) error { return nil }, MaxAge: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Tick(context.Background()); e == nil || !c.Status().Quarantined {
		t.Fatal("stale health accepted")
	}
}
func TestCloseCancelsTickAndStopsRun(t *testing.T) {
	m := fixture(t)
	entered := make(chan struct{})
	var once atomic.Bool
	var apply, q atomic.Int32
	c, e := New(Options{Model: m, GroupID: "fallback", Probe: func(ctx context.Context, ep endpoints.Endpoint) (Observation, error) {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		<-ctx.Done()
		return Observation{}, ctx.Err()
	}, ApplyModel: func(context.Context, coreconfig.Model) error { apply.Add(1); return nil }, Quarantine: func(context.Context) error { q.Add(1); return nil }})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error)
	go func() { done <- c.Run(context.Background(), time.Hour) }()
	<-entered
	if e = c.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("closed run succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("run did not stop")
	}
	if apply.Load() != 0 || q.Load() != 1 || c.Status().State != "closed" {
		t.Fatal("close permitted stale apply")
	}
	if e = c.Tick(context.Background()); e == nil {
		t.Fatal("tick after close")
	}
	if e = c.UpdateModel(context.Background(), m); e == nil {
		t.Fatal("update after close")
	}
	if e = c.Close(context.Background()); e != nil || q.Load() != 1 {
		t.Fatal("close not idempotent")
	}
}
