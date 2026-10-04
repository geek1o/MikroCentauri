package dnsgate

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// Serve binds both transports at the supplied address. Cancellation closes all
// sockets and waits for outstanding bounded requests to finish.
func (g *Gate) Serve(ctx context.Context, listen string) error {
	tcp, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		return err
	}
	defer udp.Close()
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
					_ = conn.SetDeadline(time.Now().Add(g.config.Timeout))
					var size [2]byte
					if _, e := io.ReadFull(conn, size[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(size[:]))
					if n < 12 || n > g.config.MaxMessage {
						return
					}
					request := make([]byte, n)
					if _, e := io.ReadFull(conn, request); e != nil {
						return
					}
					answer := g.Handle(ctx, request)
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
		buf := make([]byte, g.config.MaxMessage+1)
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
				answer := g.Handle(ctx, request)
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
