package api

import (
	"context"
	"net/http"
	"regexp"
	"time"
)

type NodeProbeRuntime interface {
	ProbeNode(context.Context, string) (time.Duration, error)
}
type NodeProbeRequest struct {
	ID string `json:"id"`
}
type NodeProbeResult struct {
	NodeID    string    `json:"node_id"`
	Success   bool      `json:"success"`
	Code      string    `json:"code"`
	Scope     string    `json:"scope"`
	LatencyMS int64     `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at"`
	Revision  uint64    `json:"revision"`
}

var nodeProbeID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s *Server) nodeProbePost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/proxies/probe" {
		return false
	}
	var input NodeProbeRequest
	if decode(raw, &input) != nil || !nodeProbeID.MatchString(input.ID) {
		reject(w, 400, "invalid_request")
		return true
	}
	model, e := s.model()
	if e != nil {
		reject(w, 503, "model_unavailable")
		return true
	}
	active := false
	for _, node := range model.Endpoints {
		active = active || node.ID == input.ID && node.Enabled
	}
	for _, node := range model.WireGuard {
		active = active || node.ID == input.ID && node.Enabled
	}
	if !active {
		reject(w, 404, "active_endpoint_absent")
		return true
	}
	runtime, ok := s.opts.Runtime.(NodeProbeRuntime)
	if !ok {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	revision := s.view().Revision
	latency, e := runtime.ProbeNode(r.Context(), input.ID)
	result := NodeProbeResult{input.ID, e == nil, "node_verified", "fresh HTTP canary through this active endpoint in isolated socksify child; latency excludes child startup; not continuous health", max(0, latency.Milliseconds()), s.now().UTC(), revision}
	if e != nil {
		result.Code = "node_failed"
	}
	s.event("diagnostic_"+result.Code, id)
	reply(w, 200, result)
	return true
}
