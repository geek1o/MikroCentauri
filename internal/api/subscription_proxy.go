package api

import (
	"context"
	"errors"

	"mikrocentauri.local/core/internal/subscriptions"
)

// withSubscriptionProxy snapshots only one endpoint while holding the API lock.
// The potentially slow isolated process and download run after releasing it.
func (s *Server) withSubscriptionProxy(ctx context.Context, id string, operation func(context.Context, subscriptions.DialContext) error) error {
	s.mu.Lock()
	var sequence uint64
	if s.draft != nil {
		sequence = s.draft.Sequence
	}
	model, _, err := s.editableModel(sequence)
	if s.poisoned {
		err = errors.New("subscription draft unavailable")
	}
	runner := s.opts.SubscriptionProxy
	s.mu.Unlock()
	if err != nil || runner == nil || operation == nil {
		return errors.New("subscription proxy unavailable")
	}
	for _, node := range model.Endpoints {
		if node.ID == id && node.Enabled {
			return runner(ctx, node, model.DNS.Bootstrap, operation)
		}
	}
	return errors.New("subscription proxy node unavailable")
}

// SetTransport changes the path without reading back or replacing the secret URL.
func (s *SubscriptionResources) SetTransport(in SubscriptionTransportRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return errors.New("subscription registry unavailable")
	}
	next := append([]subscriptions.Spec(nil), s.specs...)
	for i, spec := range next {
		if spec.ID == in.ID {
			spec.ProxyNode = in.ProxyNode
			if validateSpec(spec) != nil {
				return errors.New("invalid subscription transport")
			}
			next[i] = spec
			if err := s.persistLocked(next); err != nil {
				return err
			}
			s.recordEvent("subscription_transport_configured")
			return nil
		}
	}
	return errors.New("subscription not configured")
}
