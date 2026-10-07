package dnsgate

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestListenUDPFailureReleasesPreviouslyBoundTCP(t *testing.T) {
	occupied, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	address := occupied.LocalAddr().String()
	if listener, e := Listen(address); e == nil {
		listener.Close()
		t.Fatal("DNS admitted startup without binding UDP")
	}
	// Listen binds TCP first. A failed UDP bind must relinquish that exact port
	// so the next startup is not blocked by a leaked, inactive TCP listener.
	tcp, e := net.Listen("tcp", address)
	if e != nil {
		t.Fatal("failed DNS startup leaked TCP listener", e)
	}
	tcp.Close()
}

type startupHandler struct{}

func (startupHandler) Handle(_ context.Context, message []byte) []byte { return message }
func TestPreboundDNSListenerCancellationReleasesBothTransports(t *testing.T) {
	listener, e := Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	for _, network := range []string{"tcp", "udp"} {
		if network == "tcp" {
			occupied, e := net.Listen(network, address)
			if e == nil {
				occupied.Close()
				listener.Close()
				t.Fatal("TCP was not bound before admission")
			}
		} else {
			occupied, e := net.ListenPacket(network, address)
			if e == nil {
				occupied.Close()
				listener.Close()
				t.Fatal("UDP was not bound before admission")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- listener.Run(ctx, startupHandler{}) }()
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS listener did not stop")
	}
	tcp, e := net.Listen("tcp", address)
	if e != nil {
		t.Fatal("TCP not released", e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp", address)
	if e != nil {
		t.Fatal("UDP not released", e)
	}
	defer udp.Close()
}
