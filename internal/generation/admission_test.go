//go:build linux || darwin

package generation

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

type engineFunc func(context.Context, string) (netip.Addr, error)

func (f engineFunc) Alias(ctx context.Context, name string) (netip.Addr, error) { return f(ctx, name) }

type ledger struct {
	mu      sync.Mutex
	items   []fakeip.Mapping
	calls   []string
	publish func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error)
}

func (l *ledger) Mappings() []fakeip.Mapping {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]fakeip.Mapping(nil), l.items...)
}
func (l *ledger) PublishAlias(ctx context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
	l.mu.Lock()
	l.calls = append(l.calls, name)
	l.mu.Unlock()
	if l.publish != nil {
		return l.publish(ctx, name, alias)
	}
	return fakeip.Mapping{Domain: name, Fake: alias, Real: addr("10.77.0.20")}, time.Second, nil
}
func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

var names = []string{"selected.test", "second.test", "third.test"}

func aliases() map[string]netip.Addr {
	return map[string]netip.Addr{names[0]: addr("198.18.0.2"), names[1]: addr("198.18.0.3"), names[2]: addr("198.18.0.4")}
}
func fixture(t *testing.T, e Engine, l Ledger) *Admission {
	t.Helper()
	a, err := New(Config{Selected: names, Capacity: 3}, e, l)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestAllAliasesCheckedBeforePublication(t *testing.T) {
	l := &ledger{}
	var queried []string
	e := engineFunc(func(ctx context.Context, name string) (netip.Addr, error) {
		if len(l.calls) != 0 {
			t.Fatal("published before full prefetch")
		}
		queried = append(queried, name)
		return aliases()[name], nil
	})
	a := fixture(t, e, l)
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(queried) != 3 || queried[0] != names[0] || len(l.calls) != 3 || l.calls[0] != names[0] {
		t.Fatalf("configured allocation order lost: %v %v", queried, l.calls)
	}
	s := a.Snapshot()
	if !s.Admitted || len(s.Bindings) != 3 {
		t.Fatal(s)
	}
	s.Bindings[0].Alias = addr("198.18.1.1")
	if a.Snapshot().Bindings[0].Alias != aliases()[names[0]] {
		t.Fatal("mutable snapshot")
	}
	for _, tc := range []struct {
		name  string
		alias netip.Addr
	}{{names[0], aliases()[names[0]]}, {"SELECTED.test.", aliases()[names[0]]}} {
		if _, _, err := a.PublishAlias(context.Background(), tc.name, tc.alias); err != nil {
			t.Fatal(err)
		}
	}
	before := len(l.calls)
	for _, tc := range []struct {
		name  string
		alias netip.Addr
	}{{"unselected.test", addr("198.18.0.9")}, {names[0], aliases()[names[1]]}} {
		if _, _, err := a.PublishAlias(context.Background(), tc.name, tc.alias); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if len(l.calls) != before {
		t.Fatal("denied request mutated ledger")
	}
}
func TestAliasAndLedgerMismatchNeverPublish(t *testing.T) {
	for _, kind := range []string{"duplicate", "outside", "changed", "unknown", "duplicate_ledger", "engine_error"} {
		t.Run(kind, func(t *testing.T) {
			values := aliases()
			l := &ledger{}
			switch kind {
			case "duplicate":
				values[names[2]] = values[names[0]]
			case "outside":
				values[names[2]] = addr("10.77.0.20")
			case "changed":
				l.items = []fakeip.Mapping{{Domain: names[2], Fake: addr("198.18.0.99")}}
			case "unknown":
				l.items = []fakeip.Mapping{{Domain: "unknown.test", Fake: addr("198.18.0.99")}}
			case "duplicate_ledger":
				l.items = []fakeip.Mapping{{Domain: names[0], Fake: values[names[0]]}, {Domain: names[0], Fake: values[names[0]]}}
			}
			a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) {
				if kind == "engine_error" && name == names[2] {
					return netip.Addr{}, errors.New("secret endpoint error")
				}
				return values[name], nil
			}), l)
			if err := a.Admit(context.Background()); err == nil {
				t.Fatal("unsafe admission accepted")
			}
			if len(l.calls) != 0 || a.Snapshot().Admitted {
				t.Fatal("mutated after mismatch")
			}
			if a.Snapshot().Reason == "secret endpoint error" {
				t.Fatal("raw error exposed")
			}
		})
	}
}
func TestRevokedAdmissionCannotResurrect(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) {
		if name == names[2] {
			close(entered)
			<-release
		}
		return aliases()[name], nil
	}), l)
	finished := make(chan error, 1)
	go func() { finished <- a.Admit(context.Background()) }()
	<-entered
	a.Revoke()
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("revoked admission succeeded")
	}
	if a.Snapshot().Admitted || len(l.calls) != 0 {
		t.Fatal("revoked epoch resurrected")
	}
}

func TestSupersededAdmissionCannotRevokeNewReceipt(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return aliases()[name], nil
	}), l)
	finished := make(chan error, 1)
	go func() { finished <- a.Admit(context.Background()) }()
	<-entered
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	epoch := a.Snapshot().Epoch
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("obsolete admission succeeded")
	}
	if snapshot := a.Snapshot(); !snapshot.Admitted || snapshot.Epoch != epoch {
		t.Fatal("obsolete admission revoked current receipt", snapshot)
	}
}

func TestCallerCancellationSuppressesSuccessfulDependency(t *testing.T) {
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) { return aliases()[name], nil }), l)
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.publish = func(_ context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		cancel()
		return fakeip.Mapping{Domain: name, Fake: alias}, time.Second, nil
	}
	if _, _, err := a.PublishAlias(ctx, names[0], aliases()[names[0]]); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled result released", err)
	}
}

func TestBeginDeniesBeforeExchangeAndBindsEpoch(t *testing.T) {
	var engineCalls atomic.Int32
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) {
		engineCalls.Add(1)
		return aliases()[name], nil
	}), l)
	if _, _, err := a.Begin(context.Background(), names[0]); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if engineCalls.Load() != 0 || len(l.calls) != 0 {
		t.Fatal("unadmitted Begin allocated")
	}
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unselected.test", "*.test"} {
		if _, _, err := a.Begin(context.Background(), name); !errors.Is(err, ErrDenied) {
			t.Fatal("unselected exchange admitted", err)
		}
	}
	op, cancel, err := a.Begin(context.Background(), "SELECTED.test.")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	a.Revoke()
	if !errors.Is(op.Err(), context.Canceled) {
		t.Fatal("revoked exchange not immediately cancelled")
	}
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if op.Err() == nil {
		t.Fatal("old exchange revived by new admission")
	}
}

func TestBeginCallerCancellation(t *testing.T) {
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) { return aliases()[name], nil }), &ledger{})
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	parent, stop := context.WithCancel(context.Background())
	op, cleanup, err := a.Begin(parent, names[0])
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	stop()
	select {
	case <-op.Done():
	case <-time.After(time.Second):
		t.Fatal("caller cancellation lost")
	}
	if _, _, err := a.Begin(parent, names[0]); !errors.Is(err, context.Canceled) {
		t.Fatal("already cancelled exchange admitted", err)
	}
}
func TestRevokeCancelsPublicationAndSuppressesLateReceipt(t *testing.T) {
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) { return aliases()[name], nil }), l)
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	l.publish = func(ctx context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		close(entered)
		<-release
		if ctx.Err() == nil {
			t.Error("operation not cancelled")
		}
		return fakeip.Mapping{Domain: name, Fake: alias}, time.Second, nil
	}
	finished := make(chan error, 1)
	go func() {
		_, _, err := a.PublishAlias(context.Background(), names[0], aliases()[names[0]])
		finished <- err
	}()
	<-entered
	a.Revoke()
	close(release)
	if err := <-finished; err == nil {
		t.Fatal("late DNS receipt released")
	}
}
func TestValidationRevokesChangedEngine(t *testing.T) {
	values := aliases()
	l := &ledger{}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) { return values[name], nil }), l)
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	values[names[1]] = addr("198.18.0.99")
	if err := a.Validate(context.Background()); err == nil {
		t.Fatal("changed engine accepted")
	}
	if a.Snapshot().Admitted || a.Snapshot().Reason != "engine_mismatch" {
		t.Fatal(a.Snapshot())
	}
	before := len(l.calls)
	if _, _, err := a.PublishAlias(context.Background(), names[0], values[names[0]]); err == nil {
		t.Fatal("revocation did not close gate")
	}
	if len(l.calls) != before {
		t.Fatal("revoked publisher mutated")
	}
}
func TestPartialPublicationMustReadmitAndRetainsReservations(t *testing.T) {
	l := &ledger{}
	l.publish = func(_ context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		mapping := fakeip.Mapping{Domain: name, Fake: alias, Real: addr("10.77.0.20")}
		if name == names[1] {
			return mapping, 0, errors.New("backend unavailable")
		}
		l.items = append(l.items, mapping)
		return mapping, time.Second, nil
	}
	a := fixture(t, engineFunc(func(_ context.Context, name string) (netip.Addr, error) { return aliases()[name], nil }), l)
	if err := a.Admit(context.Background()); err == nil {
		t.Fatal("partial admitted")
	}
	if len(l.items) != 1 || a.Snapshot().Admitted {
		t.Fatal("reservation discarded or released")
	}
	l.publish = nil
	if err := a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestConfigAndCancellation(t *testing.T) {
	l := &ledger{}
	e := engineFunc(func(ctx context.Context, name string) (netip.Addr, error) { return aliases()[name], ctx.Err() })
	for _, cfg := range []Config{{Capacity: 3}, {Selected: names, Capacity: 2}, {Selected: []string{"same.test", "SAME.test."}, Capacity: 3}, {Selected: []string{"*.test"}, Capacity: 3}, {Selected: names, Capacity: 3, Prefix: netip.MustParsePrefix("10.0.0.0/8")}} {
		if _, err := New(cfg, e, l); err == nil {
			t.Fatal("invalid config accepted", cfg)
		}
	}
	a := fixture(t, e, l)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Admit(ctx); err == nil || len(l.calls) != 0 {
		t.Fatal("cancelled admission published")
	}
	if err := a.Validate(context.Background()); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}

func TestRetiredAliasAdmittedButNotPubliclyAllocated(t *testing.T) {
	l := &ledger{items: []fakeip.Mapping{{Domain: names[1], Fake: aliases()[names[1]], Real: addr("10.77.0.20")}}}
	a, err := New(Config{Selected: names, Active: []string{names[0], names[2]}, Capacity: 4}, engineFunc(func(ctx context.Context, n string) (netip.Addr, error) { return aliases()[n], nil }), l)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(a.Snapshot().Bindings) != 3 {
		t.Fatal("retired binding omitted")
	}
	if _, _, err = a.Begin(context.Background(), names[1]); !errors.Is(err, ErrDenied) {
		t.Fatal("retired allocator exposed", err)
	}
	if _, _, err = a.PublishAlias(context.Background(), names[1], aliases()[names[1]]); !errors.Is(err, ErrDenied) {
		t.Fatal("retired alias published", err)
	}
	if err = a.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestExistingMismatchPrecedesNewAllocation(t *testing.T) {
	l := &ledger{items: []fakeip.Mapping{{Domain: names[1], Fake: aliases()[names[1]], Real: addr("10.77.0.20")}}}
	var queried []string
	a, err := New(Config{Selected: append(append([]string{}, names...), "fourth.test"), Capacity: 4}, engineFunc(func(ctx context.Context, n string) (netip.Addr, error) {
		queried = append(queried, n)
		return addr("198.18.0.99"), nil
	}), l)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.Admit(context.Background()), ErrDenied) {
		t.Fatal("accepted mismatch")
	}
	if len(queried) != 1 || queried[0] != names[1] || len(l.calls) != 0 {
		t.Fatal("allocated addition before old generation check", queried, l.calls)
	}
}
