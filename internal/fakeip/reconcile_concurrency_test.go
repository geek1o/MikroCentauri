//go:build linux || darwin

package fakeip

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type reconcileKey struct{}

func awaitProof(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("expected backend proof did not start")
	}
}

func TestReconcileAllowsPublicationBetweenProofsAndSnapshotsAppendOnlyRecords(t *testing.T) {
	firstEntered, secondEntered := make(chan struct{}), make(chan struct{})
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
		select {
		case <-releaseSecond:
		default:
			close(releaseSecond)
		}
	}()
	var mu sync.Mutex
	verified := map[string]int{}
	b := backendFuncs{ensure: func(ctx context.Context, m Mapping) error {
		if ctx.Value(reconcileKey{}) != true {
			return nil
		}
		var entered, release chan struct{}
		switch m.Domain {
		case "first.test":
			entered, release = firstEntered, releaseFirst
		case "second.test":
			entered, release = secondEntered, releaseSecond
		default:
			return nil
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, verify: func(ctx context.Context, m Mapping) error {
		if ctx.Value(reconcileKey{}) == true {
			mu.Lock()
			verified[m.Domain]++
			mu.Unlock()
		}
		return nil
	}}
	p := publisher(t, fixtureConfig(t, 4), resolverFunc(fixtureResolver), b)
	for _, domain := range []string{"first.test", "second.test", "third.test"} {
		if _, _, e := p.Publish(context.Background(), domain); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), reconcileKey{}, true), 3*time.Second)
	defer cancel()
	reconciled := make(chan error, 1)
	go func() { reconciled <- p.Reconcile(ctx) }()
	awaitProof(t, firstEntered)
	published := make(chan error, 1)
	publishing := make(chan struct{})
	go func() { close(publishing); _, _, e := p.Publish(context.Background(), "appended.test"); published <- e }()
	<-publishing
	// Queue a DNS publication behind the in-flight first proof. Its wait exceeds
	// the mutex fairness threshold; the next proof must release that same lock.
	time.Sleep(20 * time.Millisecond)
	close(releaseFirst)
	select {
	case e := <-published:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS publication waited for the entire reconciliation sweep")
	}
	awaitProof(t, secondEntered)
	select {
	case e := <-reconciled:
		t.Fatal("reconcile returned before every snapshot record was proven", e)
	default:
	}
	close(releaseSecond)
	if e := <-reconciled; e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, domain := range []string{"first.test", "second.test", "third.test"} {
		if verified[domain] != 1 {
			t.Fatal("snapshot record proof omitted", verified)
		}
	}
	if verified["appended.test"] != 0 {
		t.Fatal("sweep chased newly appended records", verified)
	}
	mappings := p.Mappings()
	if len(mappings) != 4 || mappings[3].Domain != "appended.test" || mappings[3].Fake == mappings[0].Fake {
		t.Fatal("append changed immutable reservations", mappings)
	}
}
func TestReconcileCloseBetweenRecordsDeniesCompletion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	calls := 0
	b := backendFuncs{ensure: func(ctx context.Context, m Mapping) error {
		if ctx.Value(reconcileKey{}) != true {
			return nil
		}
		calls++
		if m.Domain == "first.test" {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}
	p := publisher(t, fixtureConfig(t, 2), resolverFunc(fixtureResolver), b)
	for _, name := range []string{"first.test", "second.test"} {
		if _, _, e := p.Publish(context.Background(), name); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), reconcileKey{}, true), 3*time.Second)
	defer cancel()
	reconciled := make(chan error, 1)
	go func() { reconciled <- p.Reconcile(ctx) }()
	awaitProof(t, entered)
	closing, closed := make(chan struct{}), make(chan error, 1)
	go func() { close(closing); closed <- p.Close() }()
	<-closing
	time.Sleep(20 * time.Millisecond)
	close(release)
	if e := <-closed; e != nil {
		t.Fatal(e)
	}
	if e := <-reconciled; !errors.Is(e, ErrClosed) {
		t.Fatal("closed publisher reported readiness", e)
	}
	if calls != 1 {
		t.Fatal("reconciliation continued after Close", calls)
	}
}
func TestReconcileCancellationPreservesAtomicPendingReservation(t *testing.T) {
	c := fixtureConfig(t, 2)
	entered := make(chan struct{})
	armed := false
	b := backendFuncs{ensure: func(ctx context.Context, m Mapping) error {
		if !armed {
			return errors.New("lost ensure reply")
		}
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	p := publisher(t, c, resolverFunc(fixtureResolver), b)
	_, _, e := p.Publish(context.Background(), "pending.test")
	if e == nil {
		t.Fatal("fixture failed to reserve pending intent")
	}
	before := readJournal(t, c.Directory)
	armed = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Reconcile(ctx) }()
	awaitProof(t, entered)
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	after := readJournal(t, c.Directory)
	if len(after.Records) != 1 || after.Records[0].Ready || after.Records[0].Mapping != before.Records[0].Mapping || after.Records[0].PreviousMapping != nil {
		t.Fatal("cancel lost pending immutable intent", after)
	}
	if e := p.Close(); e != nil {
		t.Fatal(e)
	}
	reopened := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	mapping, _, e := reopened.Publish(context.Background(), "pending.test")
	if e != nil || mapping != before.Records[0].Mapping {
		t.Fatal("cancelled intent did not recover without reassignment", mapping, e)
	}
}
