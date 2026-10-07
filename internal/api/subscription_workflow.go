package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/subscriptions"
)

// SubscriptionMetadata intentionally omits the private provider URL.
type SubscriptionMetadata struct {
	ID      string `json:"id"`
	Include string `json:"include,omitempty"`
	Exclude string `json:"exclude,omitempty"`
}
type SubscriptionDeleteRequest struct {
	ID string `json:"id"`
}
type SubscriptionImportRequest struct {
	ID            string   `json:"id"`
	NodeIDs       []string `json:"node_ids"`
	DraftRevision uint64   `json:"draft_revision"`
}
type SubscriptionImportResult struct {
	DraftRevision uint64 `json:"draft_revision"`
	BaseRevision  uint64 `json:"base_revision"`
	Imported      int    `json:"imported"`
}

func (s *SubscriptionResources) persistLocked(next []subscriptions.Spec) error {
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if config.WriteAtomic(filepath.Join(s.dir, "subscription-specs.json"), b) != nil {
		s.poisoned = true
		return errors.New("subscription specification persistence failed")
	}
	s.specs = next
	return nil
}

// Delete removes the provider registry entry, retaining active model endpoints
// and private last-known-good cache. It never changes the running core.
func (s *SubscriptionResources) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return errors.New("subscription registry requires reopen")
	}
	next := make([]subscriptions.Spec, 0, len(s.specs))
	found := false
	for _, v := range s.specs {
		if v.ID == id {
			found = true
		} else {
			next = append(next, v)
		}
	}
	if !found {
		return errors.New("subscription not configured")
	}
	if e := s.persistLocked(next); e != nil {
		return e
	}
	s.recordEvent("subscription_deleted")
	return nil
}
func (s *SubscriptionResources) Metadata() ([]SubscriptionMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return nil, errors.New("subscription registry requires reopen")
	}
	result := make([]SubscriptionMetadata, 0, len(s.specs))
	for _, v := range s.specs {
		result = append(result, SubscriptionMetadata{v.ID, v.Include, v.Exclude})
	}
	return result, nil
}
func (s *SubscriptionResources) metadataLocked(metadata []SubscriptionMetadata) ([]subscriptions.Spec, error) {
	if s.poisoned || s.lock == nil || len(metadata) > 64 {
		return nil, errors.New("invalid subscription metadata")
	}
	next := append([]subscriptions.Spec(nil), s.specs...)
	seen := map[string]bool{}
	for _, v := range metadata {
		if seen[v.ID] {
			return nil, errors.New("duplicate subscription metadata")
		}
		seen[v.ID] = true
		found := false
		for i, spec := range next {
			if spec.ID == v.ID {
				spec.Include = v.Include
				spec.Exclude = v.Exclude
				if validateSpec(spec) != nil {
					return nil, errors.New("invalid subscription metadata")
				}
				next[i] = spec
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("subscription credentials unavailable")
		}
	}
	return next, nil
}
func (s *SubscriptionResources) ValidateMetadata(metadata []SubscriptionMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, e := s.metadataLocked(metadata)
	return e
}
func (s *SubscriptionResources) RestoreMetadata(metadata []SubscriptionMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, e := s.metadataLocked(metadata)
	if e != nil {
		return e
	}
	return s.persistLocked(next)
}
func (s *SubscriptionResources) selected(id string, ids []string) ([]endpoints.Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil || len(ids) < 1 || len(ids) > 128 {
		return nil, errors.New("invalid subscription selection")
	}
	found := false
	for _, v := range s.specs {
		if v.ID == id {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("subscription not configured")
	}
	state, e := s.manager.Load(id)
	if e != nil {
		return nil, errors.New("subscription cache unavailable")
	}
	wanted := map[string]bool{}
	for _, v := range ids {
		if wanted[v] {
			return nil, errors.New("duplicate selected node")
		}
		wanted[v] = true
	}
	result := make([]endpoints.Endpoint, 0, len(ids))
	for _, v := range state.Nodes {
		if wanted[v.ID] {
			result = append(result, v)
			delete(wanted, v.ID)
		}
	}
	if len(wanted) > 0 {
		return nil, errors.New("selected node unavailable")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// subscriptionWorkflow is called with the Server mutation mutex held.
func (s *Server) subscriptionWorkflow(w http.ResponseWriter, r *http.Request, raw []byte, requestID string) bool {
	if r.URL.Path != "/api/v1/subscriptions/delete" && r.URL.Path != "/api/v1/subscriptions/import" {
		return false
	}
	if s.opts.Subscriptions == nil {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	if r.URL.Path == "/api/v1/subscriptions/delete" {
		var in SubscriptionDeleteRequest
		if decode(raw, &in) != nil || !subscriptionID.MatchString(in.ID) {
			reject(w, 400, "invalid_request")
			return true
		}
		if s.opts.Subscriptions.Delete(in.ID) != nil {
			reject(w, 503, "subscription_delete_failed")
			return true
		}
		s.event("subscription_deleted", requestID)
		reply(w, 200, map[string]string{"id": in.ID})
		return true
	}
	var in SubscriptionImportRequest
	if decode(raw, &in) != nil || !subscriptionID.MatchString(in.ID) || len(in.NodeIDs) < 1 || len(in.NodeIDs) > 128 {
		reject(w, 400, "invalid_request")
		return true
	}
	m, baseRevision, e := s.editableModel(in.DraftRevision)
	if e != nil {
		reject(w, 409, "stale_draft")
		return true
	}
	nodes, e := s.opts.Subscriptions.selected(in.ID, in.NodeIDs)
	if e != nil {
		reject(w, 400, "invalid_subscription_selection")
		return true
	}
	for _, node := range nodes {
		replaced := false
		for i, old := range m.Endpoints {
			if old.ID == node.ID {
				node.Enabled = old.Enabled
				m.Endpoints[i] = node
				replaced = true
				break
			}
		}
		if !replaced {
			node.Enabled = true
			m.Endpoints = append(m.Endpoints, node)
		}
	}
	if m.Validate() != nil || s.validate(r.Context(), baseRevision, m) != nil {
		reject(w, 400, "invalid_model")
		return true
	}
	if s.view().Revision != baseRevision || s.view().Pending {
		reject(w, 409, "stale_draft")
		return true
	}
	if s.saveDraft(m) != nil {
		reject(w, 503, "draft_persistence_failed")
		return true
	}
	s.opts.Subscriptions.recordEvent("subscription_imported_to_draft")
	s.event("subscription_imported_to_draft", requestID)
	reply(w, 200, SubscriptionImportResult{s.draft.Sequence, s.draft.BaseRevision, len(nodes)})
	return true
}

// Run refreshes configured providers serially on an operator-owned interval.
// It never imports endpoints or applies network configuration. There is no
// immediate retry; each failed provider is attempted at most once per tick.
func (s *SubscriptionResources) Run(ctx context.Context, interval time.Duration) error {
	if interval < time.Minute || interval > 24*time.Hour {
		return errors.New("subscription refresh interval outside bounds")
	}
	s.mu.Lock()
	if s.running || s.poisoned || s.lock == nil {
		s.mu.Unlock()
		return errors.New("subscription refresher unavailable")
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			metadata, e := s.Metadata()
			if e != nil {
				return e
			}
			for _, spec := range metadata {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				attempt, cancel := context.WithTimeout(ctx, 45*time.Second)
				_, _ = s.Refresh(attempt, spec.ID)
				cancel()
			}
		}
	}
}

// Events returns a bounded redacted history, including unattended refreshes.
// Its lock is independent of both the server and registry mutation locks.
func (s *SubscriptionResources) Events() []Event {
	if s == nil {
		return []Event{}
	}
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	return append([]Event{}, s.events...)
}
func (s *SubscriptionResources) recordEvent(code string) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	level := "info"
	if code == "subscription_refresh_failed" {
		level = "warning"
	}
	s.events = append(s.events, Event{Timestamp: time.Now().UTC(), Level: level, Component: "subscriptions", Event: code})
	if len(s.events) > 128 {
		s.events = s.events[len(s.events)-128:]
	}
}
