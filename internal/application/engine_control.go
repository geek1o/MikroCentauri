package application

import (
	"context"
	"errors"
	"mikrocentauri.local/core/internal/enginecontrol"
	"net"
	"strconv"
)

func (r *Runtime) control() (*enginecontrol.Client, error) {
	if r.Profile.ControlPort == 0 {
		return nil, errors.New("engine controller disabled")
	}
	return enginecontrol.New(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.Profile.ControlPort))), r.Profile.ControlSecret)
}
func (r *Runtime) EngineSnapshot(ctx context.Context) (result map[string]enginecontrol.Proxy, err error) {
	err = r.Host.Inspect(ctx, func(ctx context.Context) error {
		c, e := r.control()
		if e != nil {
			return e
		}
		result, e = c.Snapshot(ctx)
		return e
	})
	return
}
func (r *Runtime) EngineSelect(ctx context.Context, group, node string, revision uint64) error {
	return r.Host.Control(ctx, func(ctx context.Context) error {
		if r.View().Revision != revision {
			return errors.New("stale engine revision")
		}
		m, e := r.Model()
		if e != nil {
			return e
		}
		allowed := false
		for _, g := range m.Groups {
			if g.ID == group && g.Type == "selector" {
				for _, id := range g.Members {
					allowed = allowed || id == node
				}
			}
		}
		if !allowed {
			return errors.New("invalid active selector member")
		}
		c, e := r.control()
		if e != nil {
			return e
		}
		return c.Select(ctx, group, node)
	})
}
func (r *Runtime) EngineDelay(ctx context.Context, node string) (int64, error) {
	var client *enginecontrol.Client
	err := r.Host.Inspect(ctx, func(ctx context.Context) error {
		m, e := r.Model()
		if e != nil {
			return e
		}
		found := false
		for _, n := range m.Endpoints {
			found = found || n.ID == node && n.Enabled
		}
		if !found {
			return errors.New("active node absent")
		}
		client, e = r.control()
		return e
	})
	if err != nil {
		return 0, err
	}
	// URLTest addresses this outbound directly. It does not mutate selector state
	// and must not hold the activation lock while waiting on a remote server.
	return client.Delay(ctx, node)
}
