package dnsgate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

type publisherFunc func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error)

func (p publisherFunc) PublishAlias(c context.Context, s string, a netip.Addr) (fakeip.Mapping, time.Duration, error) {
	return p(c, s, a)
}

func query(name string, kind uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, 0x1234)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = appendName(b, name)
	b = binary.BigEndian.AppendUint16(b, kind)
	return binary.BigEndian.AppendUint16(b, 1)
}

func upstream(t *testing.T, reply func([]byte) []byte) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(h[:]))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				r := reply(b)
				packet := binary.BigEndian.AppendUint16(nil, uint16(len(r)))
				_ = writeAll(c, append(packet, r...))
			}()
		}
	}()
	return listener.Addr().String()
}

func goodReply(req []byte) []byte {
	q, _ := parse(req, 4096)
	return response(req, q.questions[0], []byte{198, 18, 0, 3}, 30)
}
func successfulPublisher(_ context.Context, domain string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
	return verifiedMapping(domain, alias), 7 * time.Second, nil
}

func verifiedMapping(domain string, alias netip.Addr) fakeip.Mapping {
	return fakeip.Mapping{Domain: domain, Fake: alias, Real: netip.MustParseAddr("10.77.0.20")}
}
func newGate(t *testing.T, address string, p Publisher) *Gate {
	t.Helper()
	g, e := New(Config{InternalAddress: address, Selected: []string{"selected.test"}}, p)
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func assertFailure(t *testing.T, b []byte) {
	t.Helper()
	m, e := parse(b, 4096)
	if e != nil || m.flags&15 != 2 || len(m.answers) != 0 {
		t.Fatalf("expected SERVFAIL without answers: %x (%v)", b, e)
	}
}

func TestPublicationWithheldUntilRouterVerification(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan []byte, 1)
	p := publisherFunc(func(ctx context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		if name != "selected.test" || alias.String() != "198.18.0.3" {
			t.Errorf("wrong publication: %s %s", name, alias)
		}
		close(entered)
		select {
		case <-release:
			return verifiedMapping(name, alias), 7 * time.Second, nil
		case <-ctx.Done():
			return fakeip.Mapping{}, 0, ctx.Err()
		}
	})
	g := newGate(t, upstream(t, goodReply), p)
	go func() { done <- g.Handle(context.Background(), query("selected.test", 1)) }()
	<-entered
	select {
	case answer := <-done:
		t.Fatalf("answer released before proof: %x", answer)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	m, e := parse(<-done, 4096)
	if e != nil || len(m.answers) != 1 || m.answers[0].ttl != 7 {
		t.Fatalf("bad verified response: %+v %v", m, e)
	}
}

func TestPublisherFailureNeverReleasesAlias(t *testing.T) {
	g := newGate(t, upstream(t, goodReply), publisherFunc(func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
		return fakeip.Mapping{}, 0, errors.New("router verification failed")
	}))
	assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
}

func TestPublisherMustConfirmExactMapping(t *testing.T) {
	cases := map[string]func(*fakeip.Mapping){
		"wrong alias":              func(m *fakeip.Mapping) { m.Fake = netip.MustParseAddr("198.18.0.4") },
		"wrong domain":             func(m *fakeip.Mapping) { m.Domain = "other.test" },
		"noncanonical domain":      func(m *fakeip.Mapping) { m.Domain = "Selected.test." },
		"missing real address":     func(m *fakeip.Mapping) { m.Real = netip.Addr{} },
		"synthetic real address":   func(m *fakeip.Mapping) { m.Real = netip.MustParseAddr("198.19.0.1") },
		"IPv6 real address":        func(m *fakeip.Mapping) { m.Real = netip.MustParseAddr("2001:db8::1") },
		"unspecified real address": func(m *fakeip.Mapping) { m.Real = netip.IPv4Unspecified() },
		"multicast real address":   func(m *fakeip.Mapping) { m.Real = netip.MustParseAddr("224.0.0.1") },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			g := newGate(t, upstream(t, goodReply), publisherFunc(func(_ context.Context, domain string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
				mapping := verifiedMapping(domain, alias)
				alter(&mapping)
				return mapping, 30 * time.Second, nil
			}))
			assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
		})
	}
}

func TestSelectedAAAAAndUnsupportedType(t *testing.T) {
	var calls atomic.Int32
	g := newGate(t, upstream(t, func(b []byte) []byte { calls.Add(1); return goodReply(b) }), publisherFunc(func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
		calls.Add(1)
		return fakeip.Mapping{}, time.Second, nil
	}))
	m, e := parse(g.Handle(context.Background(), query("selected.test", 28)), 4096)
	if e != nil || m.flags&15 != 0 || len(m.answers) != 0 {
		t.Fatalf("AAAA not empty NOERROR: %+v", m)
	}
	// TXT, SVCB and HTTPS must not expose an alternate route around managed A/AAAA.
	for _, qtype := range []uint16{16, 64, 65} {
		assertFailure(t, g.Handle(context.Background(), query("selected.test", qtype)))
	}
	if calls.Load() != 0 {
		t.Fatal("AAAA or unsupported request reached allocator/publisher")
	}
}

func TestUnselectedPassthroughAndAliasRejection(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "real", true: "alias"}[alias], func(t *testing.T) {
			var pub atomic.Int32
			var returned []byte
			g := newGate(t, upstream(t, func(b []byte) []byte {
				q, _ := parse(b, 4096)
				a := []byte{10, 77, 0, 20}
				if alias {
					a = []byte{198, 19, 255, 254}
				}
				returned = response(b, q.questions[0], a, 30)
				return returned
			}), publisherFunc(func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				pub.Add(1)
				return fakeip.Mapping{}, time.Second, nil
			}))
			b := g.Handle(context.Background(), query("unselected.test", 1))
			if alias {
				assertFailure(t, b)
			} else if string(b) != string(returned) {
				t.Fatal("normal response was altered")
			}
			if pub.Load() != 0 {
				t.Fatal("unselected name published")
			}
		})
	}
}

func TestCraftedInternalResponsesRejected(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"wrong id":       func(b []byte) []byte { r := goodReply(b); r[0] ^= 1; return r },
		"wrong question": func(b []byte) []byte { return response(b, question{"other.test", 1, 1}, []byte{198, 18, 0, 3}, 30) },
		"wrong answer owner": func(b []byte) []byte {
			r := goodReply(b)
			q, _ := parse(b, 4096)
			off := len(response(b, q.questions[0], nil, 0))
			r[off+1] = 0
			return r
		},
		"not alias": func(b []byte) []byte {
			q, _ := parse(b, 4096)
			return response(b, q.questions[0], []byte{10, 77, 0, 20}, 30)
		},
		"truncated":    func(b []byte) []byte { r := goodReply(b); r[2] |= 2; return r },
		"two answers":  func(b []byte) []byte { r := goodReply(b); r[7] = 2; return r },
		"pointer loop": func(b []byte) []byte { r := goodReply(b); r[12] = 0xc0; r[13] = 12; return r },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			g := newGate(t, upstream(t, fn), publisherFunc(func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
				calls.Add(1)
				return fakeip.Mapping{}, time.Second, nil
			}))
			assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
			if calls.Load() != 0 {
				t.Fatal("invalid internal response reached publisher")
			}
		})
	}
}

func TestMalformedAndMultipleQuestionsRejected(t *testing.T) {
	g := newGate(t, upstream(t, goodReply), publisherFunc(successfulPublisher))
	requests := [][]byte{{}, {0x12, 0x34}, query("selected.test", 1)}
	requests[2][5] = 2
	for _, b := range requests {
		assertFailure(t, g.Handle(context.Background(), b))
	}
}

func TestAdditionalSectionAliasLeakRejected(t *testing.T) {
	g := newGate(t, upstream(t, func(req []byte) []byte {
		q, _ := parse(req, 4096)
		r := response(req, q.questions[0], []byte{10, 77, 0, 20}, 30)
		binary.BigEndian.PutUint16(r[10:], 1)
		r = appendName(r, "selected.test")
		r = binary.BigEndian.AppendUint16(r, 1)
		r = binary.BigEndian.AppendUint16(r, 1)
		r = binary.BigEndian.AppendUint32(r, 30)
		r = binary.BigEndian.AppendUint16(r, 4)
		return append(r, 198, 18, 0, 3)
	}), publisherFunc(successfulPublisher))
	assertFailure(t, g.Handle(context.Background(), query("unselected.test", 1)))
}

func TestUnverifiedOrExpiredLeaseRejected(t *testing.T) {
	for _, duration := range []time.Duration{0, -time.Second} {
		g := newGate(t, upstream(t, goodReply), publisherFunc(func(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error) {
			return fakeip.Mapping{}, duration, nil
		}))
		assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
	}
}

func TestConfigRejectsRemoteInternalResolver(t *testing.T) {
	if _, err := New(Config{InternalAddress: "10.77.0.20:5354", Selected: []string{"selected.test"}}, publisherFunc(successfulPublisher)); err == nil {
		t.Fatal("untrusted internal allocator accepted")
	}
}

func FuzzCodec(f *testing.F) {
	f.Add(query("selected.test", 1))
	f.Add([]byte{0x12, 0x34})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parse(b, 4096)
		m, err := parse(failure(b, nil), 4096)
		if err != nil || m.flags&15 != 2 || len(m.answers) != 0 {
			t.Fatal("malformed input leaked an answer")
		}
	})
}

func TestPublisherCancellationAndTTLCap(t *testing.T) {
	g := newGate(t, upstream(t, goodReply), publisherFunc(func(ctx context.Context, _ string, _ netip.Addr) (fakeip.Mapping, time.Duration, error) {
		<-ctx.Done()
		return fakeip.Mapping{}, 0, ctx.Err()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	assertFailure(t, g.Handle(ctx, query("selected.test", 1)))
	g.publisher = publisherFunc(func(_ context.Context, domain string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		return verifiedMapping(domain, alias), 300 * time.Second, nil
	})
	m, e := parse(g.Handle(context.Background(), query("selected.test", 1)), 4096)
	if e != nil || m.answers[0].ttl != 30 {
		t.Fatal("internal TTL exceeded")
	}
}

func TestUDPAndTCPServe(t *testing.T) {
	address := upstream(t, goodReply)
	g := newGate(t, address, publisherFunc(successfulPublisher))
	reserve, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	listen := reserve.Addr().String()
	_ = reserve.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Serve(ctx, listen) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	var tcp net.Conn
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		tcp, e = net.DialTimeout("tcp", listen, 20*time.Millisecond)
		if e == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	_ = tcp.SetDeadline(time.Now().Add(time.Second))
	req := query("selected.test", 1)
	packet := binary.BigEndian.AppendUint16(nil, uint16(len(req)))
	if e = writeAll(tcp, append(packet, req...)); e != nil {
		t.Fatal(e)
	}
	var size [2]byte
	if _, e = io.ReadFull(tcp, size[:]); e != nil {
		t.Fatal(e)
	}
	answer := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, e = io.ReadFull(tcp, answer); e != nil {
		t.Fatal(e)
	}
	m, e := parse(answer, 4096)
	if e != nil || len(m.answers) != 1 {
		t.Fatal("TCP did not return verified answer")
	}
	udp, e := net.Dial("udp", listen)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(time.Second))
	if _, e = udp.Write(req); e != nil {
		t.Fatal(e)
	}
	buffer := make([]byte, 4096)
	n, e := udp.Read(buffer)
	if e != nil {
		t.Fatal(e)
	}
	m, e = parse(buffer[:n], 4096)
	if e != nil || len(m.answers) != 1 {
		t.Fatal("UDP did not return verified answer")
	}
}
