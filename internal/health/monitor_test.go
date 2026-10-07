package health

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type checkerFunc func(context.Context) error

func (f checkerFunc) Check(ctx context.Context) error { return f(ctx) }
func TestHysteresisTimeline(t *testing.T) {
	fail := false
	m, err := NewMonitor(checkerFunc(func(context.Context) error {
		if fail {
			return errors.New("failure")
		}
		return nil
	}), Settings{})
	if err != nil {
		t.Fatal(err)
	}
	m.Sample(context.Background())
	if s := m.Snapshot(); s.Ready || s.Samples != 0 {
		t.Fatalf("no local readiness: %+v", s)
	}
	m.SetLocalReady(true)
	for n := 1; n <= 3; n++ {
		m.Sample(context.Background())
		if m.Snapshot().Ready != (n == 3) {
			t.Fatalf("startup sample %d: %+v", n, m.Snapshot())
		}
	}
	fail = true
	m.Sample(context.Background())
	if !m.Snapshot().Ready {
		t.Fatal("single failure should debounce")
	}
	fail = false
	m.Sample(context.Background())
	if !m.Snapshot().Ready {
		t.Fatal("success should reset failure count")
	}
	fail = true
	m.Sample(context.Background())
	m.Sample(context.Background())
	if m.Snapshot().Ready {
		t.Fatal("two failures must close gate")
	}
	fail = false
	for n := 1; n <= 3; n++ {
		m.Sample(context.Background())
		if m.Snapshot().Ready != (n == 3) {
			t.Fatalf("recovery sample %d", n)
		}
	}
	m.SetLocalReady(false)
	if m.Snapshot().Ready {
		t.Fatal("local failure must close gate immediately")
	}
	m.SetLocalReady(true)
	m.Sample(context.Background())
	if m.Snapshot().Ready {
		t.Fatal("restart must requalify")
	}
}
func TestCanceledSamplesAndOwnedTimeout(t *testing.T) {
	m, _ := NewMonitor(checkerFunc(func(ctx context.Context) error { return context.DeadlineExceeded }), Settings{})
	m.SetLocalReady(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Sample(ctx)
	if m.Snapshot().Samples != 0 {
		t.Fatal("pre-canceled sample counted")
	}
	m.Sample(context.Background())
	if m.Snapshot().ConsecutiveFailures != 1 {
		t.Fatal("probe-owned timeout must count")
	}
	m.checker = checkerFunc(func(ctx context.Context) error { cancel(); return ctx.Err() })
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	m.Sample(ctx)
	if m.Snapshot().Samples != 1 {
		t.Fatal("caller cancellation counted")
	}
}
func TestInFlightInvalidatedByLocalRestart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	m, _ := NewMonitor(checkerFunc(func(context.Context) error { close(entered); <-release; return nil }), Settings{Successes: 1})
	m.SetLocalReady(true)
	done := make(chan struct{})
	go func() { m.Sample(context.Background()); close(done) }()
	<-entered
	m.SetLocalReady(false)
	m.SetLocalReady(true)
	close(release)
	<-done
	if s := m.Snapshot(); s.Ready || s.Samples != 0 {
		t.Fatalf("stale probe accepted: %+v", s)
	}
}
func TestConcurrentMonitor(t *testing.T) {
	m, _ := NewMonitor(checkerFunc(func(context.Context) error { return nil }), Settings{})
	m.SetLocalReady(true)
	var wg sync.WaitGroup
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.Sample(context.Background()); _ = m.Snapshot() }()
	}
	wg.Wait()
	if s := m.Snapshot(); !s.Ready || s.Samples != 20 {
		t.Fatalf("bad concurrent state %+v", s)
	}
}
func TestInvalidSettings(t *testing.T) {
	if _, err := NewMonitor(nil, Settings{}); err == nil {
		t.Fatal("nil checker")
	}
	if _, err := NewMonitor(checkerFunc(func(context.Context) error { return nil }), Settings{Failures: -1}); err == nil {
		t.Fatal("negative threshold")
	}
}
