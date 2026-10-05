package realdns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func answer(q []byte) []byte { b := append([]byte(nil), q...); b[2] = 0x81; b[3] = 0x80; return b }
func addRR(b []byte, owner []byte, kind uint16, ttl uint32, data []byte) []byte {
	b = append(b, owner...)
	b = binary.BigEndian.AppendUint16(b, kind)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}
func query() []byte {
	b := make([]byte, 12)
	b[1] = 7
	b[2] = 1
	b[5] = 1
	b = appendName(b, "selected.test")
	return append(b, 0, 1, 0, 1)
}
func aResponse(q []byte) []byte {
	b := answer(q)
	b[7] = 1
	return addRR(b, []byte{0xc0, 12}, 1, 17, []byte{10, 77, 0, 20})
}
func cnameResponse(q []byte) []byte {
	b := answer(q)
	b[7] = 4
	// CNAME target compresses the suffix "test" in the original question.
	target := []byte{6, 't', 'a', 'r', 'g', 'e', 't', 0xc0, 21}
	targetOffset := len(b) + 12
	b = addRR(b, []byte{0xc0, 12}, 5, 9, target)
	owner := []byte{0xc0 | byte(targetOffset>>8), byte(targetOffset)}
	b = addRR(b, owner, 1, 20, []byte{10, 77, 0, 21})
	b = addRR(b, owner, 1, 7, []byte{10, 77, 0, 20})
	b = addRR(b, owner, 1, 12, []byte{10, 77, 0, 20})
	return b
}

func fixture(t *testing.T, handler func(net.Conn, []byte)) string {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(h[:]))
				b := make([]byte, n)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				handler(c, b)
			}()
		}
	}()
	return ln.Addr().String()
}
func writeReply(c net.Conn, b []byte) {
	f := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	f = append(f, b...)
	c.Write(f)
}
func TestWireAAndCNAME(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func([]byte) []byte
		ttl   time.Duration
		ips   string
	}{
		{"direct", aResponse, 17 * time.Second, "10.77.0.20"},
		{"compressed CNAME multi A", cnameResponse, 7 * time.Second, "10.77.0.20,10.77.0.21"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := fixture(t, func(c net.Conn, q []byte) { writeReply(c, tc.build(q)) })
			r, e := New(Config{Address: addr})
			if e != nil {
				t.Fatal(e)
			}
			ips, ttl, e := r.ResolveA(context.Background(), "Selected.Test.")
			if e != nil {
				t.Fatal(e)
			}
			got := ""
			for i, a := range ips {
				if i > 0 {
					got += ","
				}
				got += a.String()
			}
			if got != tc.ips || ttl != tc.ttl {
				t.Fatalf("got %v %v", ips, ttl)
			}
		})
	}
}
func TestRejectedResponses(t *testing.T) {
	tests := map[string]func([]byte) []byte{
		"wrong ID":       func(q []byte) []byte { b := aResponse(q); b[0] ^= 1; return b },
		"wrong question": func(q []byte) []byte { b := aResponse(q); b[13] = 'x'; return b },
		"NXDOMAIN":       func(q []byte) []byte { b := aResponse(q); b[3] |= 3; return b },
		"TC":             func(q []byte) []byte { b := aResponse(q); b[2] |= 2; return b },
		"zero TTL": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 1, 0, []byte{10, 77, 0, 20})
		},
		"high TTL": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 1, 1<<31, []byte{10, 77, 0, 20})
		},
		"CNAME only": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 5, 10, appendName(nil, "target.test"))
		},
		"CNAME loop": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 5, 10, []byte{0xc0, 12})
		},
		"CNAME A conflict": func(q []byte) []byte {
			b := aResponse(q)
			b[7] = 2
			return addRR(b, []byte{0xc0, 12}, 5, 10, appendName(nil, "target.test"))
		},
		"CNAME conflicts": func(q []byte) []byte {
			b := answer(q)
			b[7] = 2
			b = addRR(b, []byte{0xc0, 12}, 5, 10, appendName(nil, "one.test"))
			return addRR(b, []byte{0xc0, 12}, 5, 10, appendName(nil, "two.test"))
		},
		"CNAME trailing byte": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 5, 10, []byte{0xc0, 12, 0})
		},
		"CNAME short pointer": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 5, 10, []byte{0xc0})
		},
		"pointer loop": func(q []byte) []byte { b := aResponse(q); off := len(q); b[off] = 0xc0; b[off+1] = byte(off); return b },
		"short A": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, []byte{0xc0, 12}, 1, 10, []byte{1, 2, 3})
		},
		"unrelated A": func(q []byte) []byte {
			b := answer(q)
			b[7] = 1
			return addRR(b, appendName(nil, "other.test"), 1, 10, []byte{10, 77, 0, 20})
		},
		"additional A only": func(q []byte) []byte { b := aResponse(q); b[7] = 0; b[11] = 1; return b },
		"mixed unsafe A": func(q []byte) []byte {
			b := aResponse(q)
			b[7] = 2
			return addRR(b, []byte{0xc0, 12}, 1, 10, []byte{198, 18, 0, 2})
		},
		"multicast":   func(q []byte) []byte { b := aResponse(q); copy(b[len(b)-4:], []byte{224, 0, 0, 1}); return b },
		"unspecified": func(q []byte) []byte { b := aResponse(q); copy(b[len(b)-4:], []byte{0, 0, 0, 0}); return b },
		"trailing":    func(q []byte) []byte { return append(aResponse(q), 0) },
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			q := query()
			ips, ttl, e := resolve(build(q), 7, "selected.test")
			if e == nil || len(ips) != 0 || ttl != 0 {
				t.Fatalf("accepted invalid response: %v %v %v", ips, ttl, e)
			}
		})
	}
}

func TestUnrelatedAnswerCannotShortenTTL(t *testing.T) {
	q := query()
	b := aResponse(q)
	b[7] = 2
	b = addRR(b, appendName(nil, "other.test"), 1, 0, []byte{198, 18, 0, 2})
	ips, ttl, e := resolve(b, 7, "selected.test")
	if e != nil || len(ips) != 1 || ttl != 17*time.Second {
		t.Fatalf("%v %v %v", ips, ttl, e)
	}
}
func TestCNAMEChainLimit(t *testing.T) {
	for _, count := range []int{8, 9} {
		q := query()
		b := answer(q)
		b[7] = byte(count + 1)
		owner := "selected.test"
		for i := 0; i < count; i++ {
			next := string(rune('a'+i)) + ".test"
			b = addRR(b, appendName(nil, owner), 5, 5, appendName(nil, next))
			owner = next
		}
		b = addRR(b, appendName(nil, owner), 1, 10, []byte{10, 77, 0, 20})
		_, _, e := resolve(b, 7, "selected.test")
		if (e != nil) != (count > 8) {
			t.Fatalf("chain %d: %v", count, e)
		}
	}
}

func TestBoundedFramesAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(net.Conn, []byte)
	}{
		{"oversized", func(c net.Conn, _ []byte) { c.Write([]byte{0x10, 1}) }},
		{"short frame", func(c net.Conn, _ []byte) { c.Write([]byte{0, 12, 0}) }},
		{"no response", func(c net.Conn, _ []byte) { var b [1]byte; c.Read(b[:]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, e := New(Config{Address: fixture(t, tc.handler), Timeout: time.Second})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			timer := time.AfterFunc(20*time.Millisecond, cancel)
			defer timer.Stop()
			defer cancel()
			start := time.Now()
			ips, ttl, e := r.ResolveA(ctx, "selected.test")
			if e == nil || len(ips) != 0 || ttl != 0 || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("unbounded or accepted: %v %v %v", ips, ttl, e)
			}
		})
	}
}
func TestConfigAndCanceledContext(t *testing.T) {
	for _, cfg := range []Config{{Address: "dns.example:53"}, {Address: "0.0.0.0:53"}, {Address: "224.0.0.1:53"}, {Address: "127.0.0.1:0"}, {Address: "127.0.0.1:53", Timeout: -1}, {Address: "127.0.0.1:53", MaxMessage: 65535}} {
		if _, e := New(cfg); e == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
	r, _ := New(Config{Address: "127.0.0.1:53"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := r.ResolveA(ctx, "selected.test"); e == nil {
		t.Fatal("accepted cancellation")
	}
	if _, _, e := r.ResolveA(context.Background(), "bad..name"); e == nil {
		t.Fatal("accepted malformed name")
	}
}
func FuzzResponse(f *testing.F) {
	q := query()
	f.Add(aResponse(q))
	f.Add(cnameResponse(q))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		ips, ttl, e := resolve(b, 7, "selected.test")
		if e == nil {
			if len(ips) == 0 || ttl <= 0 {
				t.Fatal("empty success")
			}
			for _, a := range ips {
				if !a.Is4() || netip.MustParsePrefix("198.18.0.0/15").Contains(a) {
					t.Fatal("unsafe success")
				}
			}
		}
	})
}
