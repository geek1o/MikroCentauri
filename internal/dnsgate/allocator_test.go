package dnsgate

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestCanonicalQueriesBoundAllocatorNamespace(t *testing.T) {
	var calls atomic.Int32
	addr := upstream(t, func(b []byte) []byte {
		calls.Add(1)
		if string(b[12:]) != string(query("selected.test", 1)[12:]) || binary.BigEndian.Uint16(b[10:]) != 0 {
			t.Errorf("noncanonical query: %x", b)
		}
		return goodReply(b)
	})
	g := newGate(t, addr, publisherFunc(successfulPublisher))
	for _, name := range []string{"selected.test", "SELECTED.TEST", "SeLeCtEd.TeSt"} {
		req := query(name, 1)
		// Client EDNS is stripped for the selected allocator path.
		binary.BigEndian.PutUint16(req[10:], 1)
		req = append(req, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0)
		answer, _ := parse(g.Handle(context.Background(), req), 4096)
		if answer.flags&15 != 0 || len(answer.answers) != 1 {
			t.Fatal("canonical publication failed")
		}
	}
	a, err := NewAllocator(addr)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := a.Alias(context.Background(), "SELECTED.TEST.")
	if err != nil || alias != netip.MustParseAddr("198.18.0.3") || calls.Load() != 4 {
		t.Fatal(alias, err, calls.Load())
	}
}

type guardedPublisher struct {
	publisherFunc
	begin func(context.Context, string) (context.Context, context.CancelFunc, error)
}

func (p guardedPublisher) Begin(c context.Context, name string) (context.Context, context.CancelFunc, error) {
	return p.begin(c, name)
}
func TestUnadmittedGateNeverCallsAllocator(t *testing.T) {
	var calls atomic.Int32
	addr := upstream(t, func(req []byte) []byte { calls.Add(1); return goodReply(req) })
	for _, cancelled := range []bool{false, true} {
		p := guardedPublisher{publisherFunc(successfulPublisher), func(ctx context.Context, _ string) (context.Context, context.CancelFunc, error) {
			if !cancelled {
				return nil, nil, errors.New("not admitted")
			}
			ctx, stop := context.WithCancel(ctx)
			stop()
			return ctx, stop, nil
		}}
		g := newGate(t, addr, p)
		assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
	}
	if calls.Load() != 0 {
		t.Fatal("unadmitted request allocated engine state")
	}
}

func TestAllocatorRejectsInvalidResponses(t *testing.T) {
	for _, mutation := range []func([]byte) []byte{
		func(b []byte) []byte { b[0] ^= 1; return b },
		func(b []byte) []byte { copy(b[len(b)-4:], []byte{10, 0, 0, 1}); return b },
		func(b []byte) []byte { b[3] |= 2; return b },
	} {
		a, _ := NewAllocator(upstream(t, func(req []byte) []byte { return mutation(goodReply(req)) }))
		if _, err := a.Alias(context.Background(), "selected.test"); err == nil {
			t.Fatal("unsafe allocator response accepted")
		}
	}
}
