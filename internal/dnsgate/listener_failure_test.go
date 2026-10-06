package dnsgate

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIndependentTCPListenerFailureCancelsAndReleasesUDP(t *testing.T) {
	listener, e := Listen("127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	address := listener.Addr().String()
	done := make(chan error, 1)
	go func() { done <- listener.Run(context.Background(), startupHandler{}) }()
	// Leave UDP open: only TCP fails. Listener.Run must explicitly cancel its
	// sibling before waiting for all transport workers to finish.
	listener.tcp.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("transport failure concealed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("single transport failure failed to stop sibling")
	}
	udp, e := net.ListenPacket("udp", address)
	if e != nil {
		t.Fatal("failed TCP did not release UDP", e)
	}
	udp.Close()
}
