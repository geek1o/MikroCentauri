package api

import (
	"context"
	"mikrocentauri.local/core/internal/platform/routeros"
	"net/http"
)

type RouterNetworkClient interface {
	Network(context.Context) (routeros.Network, error)
}

func (s *Server) networkGet(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/api/v1/routeros/network" {
		return false
	}
	if s.opts.Router == nil {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	c, ok := s.opts.Router.Client.(RouterNetworkClient)
	if !ok {
		reject(w, 501, "adapter_not_connected")
		return true
	}
	v, e := c.Network(r.Context())
	if e != nil {
		reject(w, 503, "routeros_unavailable")
		return true
	}
	reply(w, 200, v)
	return true
}
