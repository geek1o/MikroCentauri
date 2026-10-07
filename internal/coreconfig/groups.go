package coreconfig

import (
	"errors"
	"time"
)

// Health is application observation, not the existence of a configured outbound.
type Health struct {
	Latency     time.Duration
	LastSuccess time.Time
	LastFailure time.Time
	Available   bool
}

// FallbackSelection chooses the first freshly observed available member. It
// preserves group order rather than URLTest latency ranking. No healthy member
// is an error; callers keep the current revision and close activation gates.
func FallbackSelection(g Group, health map[string]Health, now time.Time, maxAge time.Duration) (string, error) {
	if g.Type != "fallback" || maxAge <= 0 {
		return "", errors.New("invalid fallback policy")
	}
	for _, id := range g.Members {
		h, ok := health[id]
		if ok && h.Available && !h.LastSuccess.IsZero() && !h.LastSuccess.After(now) && now.Sub(h.LastSuccess) <= maxAge && !h.LastFailure.After(h.LastSuccess) {
			return id, nil
		}
	}
	return "", errors.New("no freshly healthy fallback member")
}

// Select creates a validated replacement model. It does not mutate the caller's
// group slice or switch a running sing-box process; the supervisor owns apply.
func (m Model) Select(groupID, member string) (Model, error) {
	next := m
	next.Groups = append([]Group(nil), m.Groups...)
	found := false
	for i, g := range next.Groups {
		if g.ID == groupID {
			if g.Type == "urltest" {
				return m, errors.New("automatic group cannot be manually pinned")
			}
			next.Groups[i].Selected = member
			found = true
			break
		}
	}
	if !found {
		return m, errors.New("unknown group")
	}
	if e := next.Validate(); e != nil {
		return m, e
	}
	return next, nil
}
