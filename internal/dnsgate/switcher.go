package dnsgate

import (
	"context"
	"errors"
	"sync"
)

// Switcher dispatches each question to one immutable generation. Hold cancels
// its lifetime and denies new questions; Install and Release form the next
// generation. The final epoch check covers Handle's result, not the subsequent
// transport write: callers must not claim an atomic packet-delivery boundary.
type Switcher struct {
	mu       sync.RWMutex
	handler  Handler
	held     bool
	epoch    uint64
	lifetime context.Context
	cancel   context.CancelFunc
}

// NewSwitcher starts open when handler is supplied, or held when it is nil.
func NewSwitcher(handler Handler) *Switcher {
	life, cancel := context.WithCancel(context.Background())
	return &Switcher{handler: handler, held: handler == nil, lifetime: life, cancel: cancel}
}

// Hold invalidates every in-flight request, including nonselected real DNS,
// before a replacement handler may be installed. Repeated holds remain safe.
func (s *Switcher) Hold() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.held = true
	s.epoch++
	if s.cancel != nil {
		s.cancel()
	}
}

// Install replaces a handler only while publication is held.
func (s *Switcher) Install(handler Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held {
		return errors.New("DNS generation must be held before install")
	}
	if handler == nil {
		return errors.New("DNS handler is required")
	}
	s.handler = handler
	return nil
}

// Release opens the installed generation with a fresh cancellation lifetime.
func (s *Switcher) Release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.held {
		return errors.New("DNS generation is already open")
	}
	if s.handler == nil {
		return errors.New("DNS handler is required")
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.lifetime, s.cancel = context.WithCancel(context.Background())
	s.epoch++
	s.held = false
	return nil
}

func (s *Switcher) Handle(ctx context.Context, request []byte) []byte {
	s.mu.RLock()
	if s.held || s.handler == nil || s.lifetime == nil {
		s.mu.RUnlock()
		return failure(request, nil)
	}
	handler, lifetime, epoch := s.handler, s.lifetime, s.epoch
	s.mu.RUnlock()
	linked, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(lifetime, cancel)
	defer stop()
	// AfterFunc is asynchronous; catch an already-canceled generation before
	// dispatch rather than relying on its callback scheduling.
	if lifetime.Err() != nil {
		return failure(request, nil)
	}
	answer := handler.Handle(linked, request)
	s.mu.RLock()
	valid := !s.held && s.epoch == epoch && lifetime.Err() == nil && linked.Err() == nil
	s.mu.RUnlock()
	if !valid {
		return failure(request, nil)
	}
	return answer
}
