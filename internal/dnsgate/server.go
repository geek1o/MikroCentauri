package dnsgate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Serve binds both transports at the supplied address. Cancellation closes all
// sockets and waits for outstanding bounded requests to finish.
func (g *Gate) Serve(ctx context.Context, listen string) error {
	return serve(ctx, listen, g, g.config.MaxMessage, g.config.Timeout)
}

// Handler supplies one DNS response. A dispatcher may atomically choose an
// immutable Gate at the start of each Handle call without replacing listeners.
type Handler interface {
	Handle(context.Context, []byte) []byte
}

// Serve keeps transport bounds fixed across handler generations: 4096 bytes,
// two-second socket deadlines and at most 128 concurrent requests. Handlers
// remain responsible for request validation and their own exchange deadlines.
func Serve(ctx context.Context, listen string, handler Handler) error {
	if handler == nil {
		return errors.New("DNS handler is required")
	}
	return serve(ctx, listen, handler, 4096, 2*time.Second)
}

func serve(ctx context.Context, listen string, handler Handler, maxMessage int, timeout time.Duration) error {
	listener, err := Listen(listen)
	if err != nil {
		return err
	}
	return listener.serve(ctx, handler, maxMessage, timeout)
}

// Listener binds TCP and UDP before runtime admission can become ready.
// Its owner must close it if startup fails before Serve is entered.
type Listener struct {
	tcp net.Listener
	udp net.PacketConn
}

func Listen(address string) (*Listener, error) {
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	return &Listener{tcp, udp}, nil
}
func (l *Listener) Close() error   { return errors.Join(l.tcp.Close(), l.udp.Close()) }
func (l *Listener) Addr() net.Addr { return l.tcp.Addr() }
func (l *Listener) Run(ctx context.Context, handler Handler) error {
	if handler == nil {
		return errors.New("DNS handler is required")
	}
	return l.serve(ctx, handler, 4096, 2*time.Second)
}
func (l *Listener) serve(ctx context.Context, handler Handler, maxMessage int, timeout time.Duration) error {
	tcp, udp := l.tcp, l.udp
	defer l.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = tcp.Close(); _ = udp.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, 128)
	errors := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, e := tcp.Accept()
			if e != nil {
				errors <- e
				return
			}
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				_ = conn.Close()
				return
			default:
				_ = conn.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				defer conn.Close()
				closeOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer closeOnCancel()
				for {
					_ = conn.SetDeadline(time.Now().Add(timeout))
					var size [2]byte
					if _, e := io.ReadFull(conn, size[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(size[:]))
					if n < 12 || n > maxMessage {
						return
					}
					request := make([]byte, n)
					if _, e := io.ReadFull(conn, request); e != nil {
						return
					}
					answer := handler.Handle(ctx, request)
					packet := make([]byte, 2+len(answer))
					binary.BigEndian.PutUint16(packet, uint16(len(answer)))
					copy(packet[2:], answer)
					if writeAll(conn, packet) != nil {
						return
					}
				}
			}()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, maxMessage+1)
		for {
			n, peer, e := udp.ReadFrom(buf)
			if e != nil {
				errors <- e
				return
			}
			request := append([]byte(nil), buf[:n]...)
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			default:
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				answer := handler.Handle(ctx, request)
				_, _ = udp.WriteTo(answer, peer)
			}()
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case e := <-errors:
		wasCanceled := ctx.Err() != nil
		cancel()
		if wasCanceled {
			return nil
		}
		return e
	}
}
