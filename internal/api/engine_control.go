package api

import (
	"context"
	"mikrocentauri.local/core/internal/enginecontrol"
	"net/http"
	"time"
)

type EngineControl interface {
	EngineSnapshot(context.Context) (map[string]enginecontrol.Proxy, error)
	EngineSelect(context.Context, string, string, uint64) error
	EngineDelay(context.Context, string) (int64, error)
}
type EngineGroup struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Selected string   `json:"selected"`
	Members  []string `json:"members"`
}
type EngineState struct {
	LatencyCheckedAt map[string]time.Time `json:"latency_checked_at"`
	Groups           []EngineGroup        `json:"groups"`
	Latency          map[string]int64     `json:"latency"`
	CheckedAt        time.Time            `json:"checked_at"`
	Revision         uint64               `json:"revision"`
}
type EngineSelectRequest struct {
	Group    string `json:"group"`
	Node     string `json:"node"`
	Revision uint64 `json:"revision"`
}
type EngineDelayRequest struct {
	Node     string `json:"node"`
	Revision uint64 `json:"revision"`
}
type EngineDelayResult struct {
	Node      string    `json:"node"`
	Success   bool      `json:"success"`
	LatencyMS int64     `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at"`
}

func (s *Server) engineState(ctx context.Context) (EngineState, error) {
	state := EngineState{LatencyCheckedAt: map[string]time.Time{}, Groups: []EngineGroup{}, Latency: map[string]int64{}, CheckedAt: s.now().UTC(), Revision: s.view().Revision}
	m, e := s.model()
	if e != nil {
		return state, e
	}
	raw, e := s.opts.Engine.EngineSnapshot(ctx)
	if e != nil {
		return state, e
	}
	for _, g := range m.Groups {
		p, ok := raw[g.ID]
		if !ok {
			continue
		}
		members := []string{}
		selected := ""
		for _, id := range g.Members {
			if _, ok := raw[id]; ok {
				members = append(members, id)
				if id == p.Now {
					selected = id
				}
			}
		}
		state.Groups = append(state.Groups, EngineGroup{g.ID, g.Type, selected, members})
	}
	for _, node := range m.Endpoints {
		if p, ok := raw[node.ID]; ok && len(p.History) > 0 {
			h := p.History[len(p.History)-1]
			if s.now().Sub(h.Time) < time.Minute && h.Delay >= 0 {
				state.Latency[node.ID] = h.Delay
				state.LatencyCheckedAt[node.ID] = h.Time
			}
		}
	}
	return state, nil
}
func (s *Server) enginePost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/engine/select" && r.URL.Path != "/api/v1/engine/delay" {
		return false
	}
	if s.opts.Engine == nil {
		reject(w, 501, "engine_not_connected")
		return true
	}
	m, e := s.model()
	if e != nil {
		reject(w, 503, "model_unavailable")
		return true
	}
	if r.URL.Path == "/api/v1/engine/select" {
		var in EngineSelectRequest
		if decode(raw, &in) != nil {
			reject(w, 400, "invalid_request")
			return true
		}
		if in.Revision != s.view().Revision || s.view().Pending {
			reject(w, 409, "stale_engine_revision")
			return true
		}
		allowed := false
		for _, g := range m.Groups {
			if g.ID == in.Group && g.Type == "selector" {
				for _, n := range g.Members {
					allowed = allowed || n == in.Node
				}
			}
		}
		if !allowed {
			reject(w, 400, "invalid_selector_member")
			return true
		}
		if s.opts.Engine.EngineSelect(r.Context(), in.Group, in.Node, in.Revision) != nil {
			reject(w, 503, "engine_switch_failed")
			return true
		}
		state, e := s.engineState(r.Context())
		if e != nil {
			reject(w, 503, "engine_unavailable")
			return true
		}
		confirmed := false
		for _, g := range state.Groups {
			confirmed = confirmed || g.ID == in.Group && g.Selected == in.Node
		}
		if !confirmed {
			reject(w, 503, "engine_switch_failed")
			return true
		}
		s.event("engine_selector_changed", id)
		reply(w, 200, state)
	} else {
		var in EngineDelayRequest
		if decode(raw, &in) != nil {
			reject(w, 400, "invalid_request")
			return true
		}
		if in.Revision != s.view().Revision || s.view().Pending {
			reject(w, 409, "stale_engine_revision")
			return true
		}
		allowed := false
		for _, n := range m.Endpoints {
			allowed = allowed || n.ID == in.Node && n.Enabled
		}
		if !allowed {
			reject(w, 404, "active_endpoint_absent")
			return true
		}
		latency, e := func() (int64, error) {
			s.mu.Unlock()
			defer s.mu.Lock()
			return s.opts.Engine.EngineDelay(r.Context(), in.Node)
		}()
		if s.view().Revision != in.Revision || s.view().Pending {
			reject(w, 409, "stale_engine_revision")
			return true
		}
		reply(w, 200, EngineDelayResult{in.Node, e == nil, max(0, latency), s.now().UTC()})
	}
	return true
}
