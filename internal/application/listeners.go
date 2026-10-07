package application

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"mikrocentauri.local/core/internal/dnsgate"
)

// RunListeners binds both DNS transports and the private native HTTP endpoint
// synchronously before the sole runtime runner starts. A listener failure stops
// the owner and withdraws traffic admission, including during startup recovery.
func (r *Runtime) RunListeners(ctx context.Context) error {
	ready, e := net.Listen("tcp", r.Profile.ReadinessListen)
	if e != nil {
		return errors.New("native readiness bind failed")
	}
	defer ready.Close()
	dns, e := dnsgate.Listen(r.Profile.DNSListen)
	if e != nil {
		return errors.New("DNS bind failed")
	}
	defer dns.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := &http.Server{Handler: r.NativeHandler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
	defer srv.Close()
	done := make(chan error, 3)
	go func() { done <- srv.Serve(ready) }()
	go func() { done <- dns.Run(ctx, r.DNS) }()
	go func() { done <- r.Host.Run(ctx) }()
	var result error
	select {
	case <-ctx.Done():
	case result = <-done:
	}
	wasCanceled := ctx.Err() != nil
	cancel()
	srv.Close()
	dns.Close()
	// Stop before releasing persistent owners, even when a listener died first.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := r.Host.Close(closeCtx)
	closeCancel()
	<-r.Host.Done()
	if result != nil && !errors.Is(result, http.ErrServerClosed) && !wasCanceled {
		return errors.New("native listener stopped")
	}
	return err
}
