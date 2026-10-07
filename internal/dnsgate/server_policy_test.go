package dnsgate

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type swappingHandler struct{ gate atomic.Pointer[Gate] }

func (h *swappingHandler) Handle(ctx context.Context, request []byte) []byte {
	return h.gate.Load().Handle(ctx, request)
}

func TestServeChangesGateOnExistingTCPConnection(t *testing.T) {
	internal := upstream(t, goodReply)
	real := upstream(t, func(req []byte) []byte {
		q, _ := parse(req, 4096)
		return response(req, q.questions[0], []byte{10, 77, 0, 20}, 30)
	})
	active, err := New(Config{InternalAddress: internal, Selected: []string{"selected.test"}}, publisherFunc(successfulPublisher))
	if err != nil {
		t.Fatal(err)
	}
	retired, err := New(Config{InternalAddress: internal, Retired: []string{"selected.test"}, RealAddress: real}, publisherFunc(successfulPublisher))
	if err != nil {
		t.Fatal(err)
	}
	handler := &swappingHandler{}
	handler.gate.Store(active)
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	reservation.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, address, handler) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	var conn net.Conn
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		conn, err = net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	request := query("selected.test", 1)
	ask := func() []byte {
		if err := writeAll(conn, append(binary.BigEndian.AppendUint16(nil, uint16(len(request))), request...)); err != nil {
			t.Fatal(err)
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, b); err != nil {
			t.Fatal(err)
		}
		answer, err := parse(b, 4096)
		if err != nil || len(answer.answers) != 1 {
			t.Fatalf("bad answer %x %v", b, err)
		}
		return answer.answers[0].data
	}
	if string(ask()) != string([]byte{198, 18, 0, 3}) {
		t.Fatal("active gate did not publish alias")
	}
	handler.gate.Store(retired)
	if string(ask()) != string([]byte{10, 77, 0, 20}) {
		t.Fatal("existing TCP session retained old DNS policy")
	}
}
