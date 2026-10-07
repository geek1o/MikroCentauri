package dnsgate

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

func TestObservedTerminalOutcomes(t *testing.T) {
	cases := []struct {
		name, domain, stage, reason string
		request                     []byte
		reply                       func([]byte) []byte
		publisher                   publisherFunc
		cancel                      bool
		failure                     bool
	}{
		{name: "selected timeout", domain: "selected.test", stage: "internal_exchange", reason: "deadline", failure: true,
			reply: func(b []byte) []byte { time.Sleep(150 * time.Millisecond); return goodReply(b) }},
		{name: "selected rcode", domain: "selected.test", stage: "internal_exchange", reason: "upstream_rcode", failure: true,
			reply: func(b []byte) []byte { r := goodReply(b); r[3] |= 2; return r }},
		{name: "publisher error", domain: "selected.test", stage: "publication", reason: "publisher_error", failure: true,
			publisher: func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				return fakeip.Mapping{}, 0, errors.New("https://secret:credential@private-router.example/")
			}},
		{name: "typed resolver error", domain: "selected.test", stage: "publication", reason: "resolve_error", failure: true,
			publisher: func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				return fakeip.Mapping{}, 0, &fakeip.OperationError{Operation: "resolve", Err: errors.New("private upstream failure")}
			}},
		{name: "typed ensure error", domain: "selected.test", stage: "publication", reason: "ensure_error", failure: true,
			publisher: func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				return fakeip.Mapping{}, 0, &fakeip.OperationError{Operation: "ensure", Err: errors.New("private router failure")}
			}},
		{name: "unknown operation", domain: "selected.test", stage: "publication", reason: "publisher_error", failure: true,
			publisher: func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				return fakeip.Mapping{}, 0, &fakeip.OperationError{Operation: "secret-operation.example", Err: errors.New("private failure")}
			}},
		{name: "typed deadline takes precedence", domain: "selected.test", stage: "publication", reason: "deadline", failure: true,
			publisher: func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				return fakeip.Mapping{}, 0, &fakeip.OperationError{Operation: "ensure", Err: context.DeadlineExceeded}
			}},

		{name: "publisher deadline", domain: "selected.test", stage: "publication", reason: "deadline", failure: true,
			publisher: func(ctx context.Context, _ string, _ netip.Addr) (fakeip.Mapping, time.Duration, error) {
				<-ctx.Done()
				return fakeip.Mapping{}, 0, ctx.Err()
			}},
		{name: "receipt mismatch", domain: "selected.test", stage: "publication", reason: "receipt_mismatch", failure: true,
			publisher: func(_ context.Context, domain string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
				m := verifiedMapping(domain, alias)
				m.Domain = "credential.example"
				return m, time.Second, nil
			}},
		{name: "unselected leak", stage: "alias_validation", reason: "unselected_alias_leak", request: query("private-user.example", 1), failure: true},
		{name: "invalid query", stage: "request", reason: "invalid_query", request: []byte("private malformed packet"), failure: true},
		{name: "selected canceled", domain: "selected.test", stage: "internal_exchange", reason: "canceled", cancel: true, failure: true},
		{name: "selected published", domain: "selected.test", stage: "publication", reason: "selected_published"},
		{name: "selected aaaa", domain: "selected.test", stage: "request", reason: "selected_aaaa_empty", request: query("selected.test", 28)},
		{name: "invalid internal response", domain: "selected.test", stage: "internal_exchange", reason: "invalid_response", failure: true,
			reply: func(b []byte) []byte { r := goodReply(b); r[0] ^= 1; return r }},
		{name: "real instead of alias", domain: "selected.test", stage: "alias_validation", reason: "outside_alias_range", failure: true,
			reply: func(b []byte) []byte {
				q, _ := parse(b, 4096)
				return response(b, q.questions[0], []byte{10, 77, 0, 20}, 30)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.request == nil {
				tc.request = query("selected.test", 1)
			}
			if tc.reply == nil {
				tc.reply = goodReply
			}
			if tc.publisher == nil {
				tc.publisher = successfulPublisher
			}
			var events []Event
			g, err := New(Config{InternalAddress: upstream(t, tc.reply), Selected: []string{"selected.test"}, Timeout: 100 * time.Millisecond,
				Observe: func(e Event) { events = append(events, e) }}, tc.publisher)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			answer := g.Handle(ctx, tc.request)
			if tc.failure {
				assertFailure(t, answer)
			} else if m, err := parse(answer, 4096); err != nil || m.flags&15 != 0 {
				t.Fatalf("unexpected response: %x %v", answer, err)
			}
			if len(events) != 1 {
				t.Fatalf("expected exactly one terminal event, got %+v", events)
			}
			e := events[0]
			if e.Stage != tc.stage || e.Reason != tc.reason || e.Domain != tc.domain || e.Duration <= 0 {
				t.Fatalf("unexpected bounded event: %+v", e)
			}
		})
	}
}

func TestObserverPreservesAnswerIncludingPanic(t *testing.T) {
	address := upstream(t, goodReply)
	request := query("selected.test", 1)
	baseline := newGate(t, address, publisherFunc(successfulPublisher)).Handle(context.Background(), request)
	for _, observer := range []func(Event){func(Event) {}, func(Event) { panic("diagnostic sink failed") }} {
		g, err := New(Config{InternalAddress: address, Selected: []string{"selected.test"}, Observe: observer}, publisherFunc(successfulPublisher))
		if err != nil {
			t.Fatal(err)
		}
		if answer := g.Handle(context.Background(), request); !bytes.Equal(answer, baseline) {
			t.Fatalf("observer changed DNS response: %x vs %x", answer, baseline)
		}
	}
}
