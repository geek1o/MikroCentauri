package dnsgate

import (
	"context"
	"testing"
	"time"
)

type handlerFunc func(context.Context, []byte) []byte

func (f handlerFunc) Handle(ctx context.Context, request []byte) []byte { return f(ctx, request) }
func realReply(request []byte) []byte {
	q, _ := parse(request, 4096)
	return response(request, q.questions[0], []byte{10, 77, 0, 20}, 30)
}

func TestSwitcherRejectsOldRealReplyAcrossGeneration(t *testing.T) {
	entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	old := handlerFunc(func(ctx context.Context, request []byte) []byte {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release // Simulate an upstream that ignores cancellation and returns real DNS.
		return realReply(request)
	})
	s := NewSwitcher(old)
	done := make(chan []byte, 1)
	go func() { done <- s.Handle(context.Background(), query("retired.test", 1)) }()
	<-entered
	s.Hold()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("old real DNS lifetime was not canceled")
	}
	assertFailure(t, s.Handle(context.Background(), query("retired.test", 1)))
	if err := s.Install(handlerFunc(realHandler)); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	close(release)
	assertFailure(t, <-done)
	reply, err := parse(s.Handle(context.Background(), query("retired.test", 1)), 4096)
	if err != nil || reply.flags&15 != 0 || len(reply.answers) != 1 {
		t.Fatalf("new generation failed: %+v %v", reply, err)
	}
}
func realHandler(_ context.Context, request []byte) []byte { return realReply(request) }

func TestSwitcherPreservesCompletedReplyAndRequiresHold(t *testing.T) {
	s := NewSwitcher(handlerFunc(realHandler))
	before := s.Handle(context.Background(), query("unselected.test", 1))
	if err := s.Install(handlerFunc(realHandler)); err == nil {
		t.Fatal("installed handler into open generation")
	}
	s.Hold()
	// A response returned before Hold is an allowed completed old request.
	reply, err := parse(before, 4096)
	if err != nil || reply.flags&15 != 0 || len(reply.answers) != 1 {
		t.Fatal("completed reply changed")
	}
	if err := s.Install(nil); err == nil {
		t.Fatal("accepted nil handler")
	}
	if err := s.Install(handlerFunc(realHandler)); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err == nil {
		t.Fatal("released already open generation")
	}
	s.Hold()
	s.Hold()
	assertFailure(t, s.Handle(context.Background(), query("unselected.test", 1)))
}

func TestSwitcherHeldStart(t *testing.T) {
	s := NewSwitcher(nil)
	assertFailure(t, s.Handle(context.Background(), query("unselected.test", 1)))
	if err := s.Release(); err == nil {
		t.Fatal("opened missing generation")
	}
	if err := s.Install(handlerFunc(realHandler)); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestSwitcherCancelsActualRetiredGateExchange(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	real := upstream(t, func(request []byte) []byte { close(entered); <-release; return realReply(request) })
	gate, err := New(Config{InternalAddress: "127.0.0.1:5354", Retired: []string{"retired.test"}, RealAddress: real, Timeout: time.Second}, publisherFunc(successfulPublisher))
	if err != nil {
		t.Fatal(err)
	}
	s := NewSwitcher(gate)
	done := make(chan []byte, 1)
	go func() { done <- s.Handle(context.Background(), query("retired.test", 1)) }()
	<-entered
	s.Hold()
	select {
	case answer := <-done:
		assertFailure(t, answer)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retired TCP exchange did not stop promptly")
	}
	close(release)
}
