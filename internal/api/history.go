package api

import (
	"sort"
	"sync"
	"time"
)

// Only internal enum codes reach the lifecycle history. Raw child output and
// dependency errors are deliberately excluded from this diagnostics boundary.
type history struct {
	mu     sync.Mutex
	events []Event
}

func (h *history) record(code string, ready bool, revision uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	level := "info"
	if !ready {
		level = "warning"
	}
	h.events = append(h.events, Event{Timestamp: time.Now().UTC(), Level: level, Component: "runtime", Event: code, RequestID: "", ConfigRevision: revision})
	if len(h.events) > 128 {
		h.events = h.events[len(h.events)-128:]
	}
}
func (h *history) snapshot() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Event{}, h.events...)
}
func (h *Host) Events() []Event { return h.history.snapshot() }
func (s *Server) logEvents() []Event {
	result := append([]Event{}, s.events...)
	if v, ok := s.opts.Runtime.(interface{ Events() []Event }); ok {
		result = append(result, v.Events()...)
	}
	if s.opts.Subscriptions != nil {
		result = append(result, s.opts.Subscriptions.Events()...)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Timestamp.Before(result[j].Timestamp) })
	if len(result) > 128 {
		result = result[len(result)-128:]
	}
	return result
}
