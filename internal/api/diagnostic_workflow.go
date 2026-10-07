package api

import (
	"context"
	"net/http"
	"time"
)

// DiagnosticRuntime probes fixed operator targets, never a browser-supplied URL
// or individual endpoint. A sample is evidence for its stated scope only.
type DiagnosticRuntime interface {
	Diagnose(context.Context, string) error
}
type DiagnosticRequest struct {
	Kind string `json:"kind"`
}
type DiagnosticResult struct {
	Kind      string    `json:"kind"`
	Success   bool      `json:"success"`
	Code      string    `json:"code"`
	Scope     string    `json:"scope"`
	LatencyMS int64     `json:"latency_ms"`
	CheckedAt time.Time `json:"checked_at"`
	Revision  uint64    `json:"revision"`
}

var diagnosticScopes = map[string]string{
	"routeros": "authenticated read-only RouterOS capability and ownership snapshot",
	"core":     "current model generation and pinned sing-box validation",
	"dns":      "configured DNS gateway TCP query for first active domain; no arbitrary target",
	"direct":   "fresh direct HTTP connection to configured literal-IP canary; valid response, no expected direct peer assertion",
	"proxy":    "fresh configured proxy canary with expected peer IP; not per-node health",
	"routing":  "active owned Linux ingress rule/table/TUN/forwarding and immutable RouterOS profile",
	"watchdog": "immutable generated watchdog/boot-guard and owned mapping profile; does not simulate failure",
}

func (s *Server) diagnosticsPost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/diagnostics/run" {
		return false
	}
	var in DiagnosticRequest
	if decode(raw, &in) != nil || diagnosticScopes[in.Kind] == "" {
		reject(w, 400, "invalid_request")
		return true
	}
	started := time.Now()
	revision := s.view().Revision
	var err error
	if in.Kind == "routeros" {
		if s.opts.Router == nil {
			reject(w, 501, "adapter_not_connected")
			return true
		}
		_, err = s.opts.Router.Snapshot(r.Context())
	} else if in.Kind == "core" {
		m, e := s.model()
		err = e
		if err == nil {
			err = s.validate(r.Context(), revision, m)
		}
	} else {
		runtime, ok := s.opts.Runtime.(DiagnosticRuntime)
		if !ok {
			reject(w, 501, "adapter_not_connected")
			return true
		}
		err = runtime.Diagnose(r.Context(), in.Kind)
	}
	result := DiagnosticResult{in.Kind, err == nil, in.Kind + "_verified", diagnosticScopes[in.Kind], time.Since(started).Milliseconds(), s.now().UTC(), revision}
	if err != nil {
		result.Code = in.Kind + "_failed"
	}
	s.event("diagnostic_"+result.Code, id)
	reply(w, 200, result)
	return true
}
