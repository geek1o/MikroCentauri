package grouphealth

import (
	"context"
	"encoding/json"
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"sync"
	"time"
)

// Callbacks must honor context deadlines. ApplyModel must commit through the
// supervisor lifecycle; it must never flip the active process's selector API.
type Options struct {
	Model               coreconfig.Model
	GroupID             string
	Probe               func(context.Context, endpoints.Endpoint) (Observation, error)
	ApplyModel          func(context.Context, coreconfig.Model) error
	Quarantine          func(context.Context) error
	MaxAge, TickTimeout time.Duration
}
type ControllerStatus struct {
	GroupID, Selected, State, Failure string
	Generation                        uint64
	Quarantined                       bool
}
type Controller struct {
	opts         Options
	mu           sync.Mutex
	apply        sync.Mutex
	model        coreconfig.Model
	group        coreconfig.Group
	generation   uint64
	cancel       context.CancelFunc
	busy         bool
	closed       bool
	closeDone    chan struct{}
	status       ControllerStatus
	observations map[string]Observation
}

func New(o Options) (*Controller, error) {
	if o.Probe == nil || o.ApplyModel == nil || o.Quarantine == nil {
		return nil, errors.New("fallback lifecycle callbacks required")
	}
	if o.MaxAge == 0 {
		o.MaxAge = 30 * time.Second
	}
	if o.TickTimeout == 0 {
		o.TickTimeout = 30 * time.Second
	}
	if o.MaxAge <= 0 || o.MaxAge > 24*time.Hour || o.TickTimeout <= 0 || o.TickTimeout > time.Minute {
		return nil, errors.New("invalid fallback observation bounds")
	}
	m, g, e := validated(o.Model, o.GroupID)
	if e != nil {
		return nil, e
	}
	return &Controller{opts: o, model: m, group: g, status: ControllerStatus{GroupID: g.ID, Selected: selection(g), State: "unobserved", Quarantined: true}, observations: map[string]Observation{}, closeDone: make(chan struct{})}, nil
}
func validated(m coreconfig.Model, id string) (coreconfig.Model, coreconfig.Group, error) {
	if m.Validate() != nil {
		return m, coreconfig.Group{}, errors.New("invalid fallback model")
	}
	raw, _ := json.Marshal(m)
	copy, e := coreconfig.Decode(raw)
	if e != nil {
		return m, coreconfig.Group{}, errors.New("invalid fallback model")
	}
	enabled := map[string]bool{}
	for _, ep := range copy.Endpoints {
		enabled[ep.ID] = ep.Enabled
	}
	for _, g := range copy.Groups {
		if g.ID == id {
			if len(g.Members) > 32 {
				return m, g, errors.New("fallback probe member limit exceeded")
			}
			if g.Type != "fallback" {
				return m, g, errors.New("group must be fallback")
			}
			for _, member := range g.Members {
				if !enabled[member] {
					return m, g, errors.New("fallback health requires enabled endpoint members")
				}
			}
			return copy, g, nil
		}
	}
	return m, coreconfig.Group{}, errors.New("unknown fallback group")
}
func selection(g coreconfig.Group) string {
	if g.Selected != "" {
		return g.Selected
	}
	return g.Members[0]
}
func (c *Controller) Status() ControllerStatus { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Controller) Observations() map[string]Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[string]Observation{}
	for k, v := range c.observations {
		m[k] = v
	}
	return m
}

// Invalidate closes gates after a separate runtime proof fails. It retains the
// last committed selection, but only a fresh tick can activate it again.
func (c *Controller) Invalidate() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("health controller closed")
	}
	c.generation++
	generation := c.generation
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.apply.Lock()
	defer c.apply.Unlock()
	return c.closeGates(generation, "runtime validation failed")
}
func (c *Controller) Tick(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("health controller closed")
	}
	if c.busy {
		c.mu.Unlock()
		return errors.New("health tick already running")
	}
	c.busy = true
	c.generation++
	generation := c.generation
	m := c.model
	g := c.group
	bounded, cancel := context.WithTimeout(ctx, c.opts.TickTimeout)
	c.cancel = cancel
	c.status.Generation = generation
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		c.busy = false
		if c.generation == generation {
			c.cancel = nil
		}
		c.mu.Unlock()
	}()
	byID := map[string]endpoints.Endpoint{}
	for _, ep := range m.Endpoints {
		byID[ep.ID] = ep
	}
	observed := map[string]Observation{}
	for _, id := range g.Members {
		if bounded.Err() != nil {
			break
		}
		ep := byID[id]
		o, e := c.opts.Probe(bounded, ep)
		now := time.Now().UTC()
		if e != nil || o.EndpointID != id || o.CheckedAt.IsZero() || o.CheckedAt.After(now) || now.Sub(o.CheckedAt) > c.opts.MaxAge || !o.Available || o.LastSuccess.IsZero() || o.LastSuccess.After(now) || now.Sub(o.LastSuccess) > c.opts.MaxAge || o.LastFailure.After(o.LastSuccess) || o.Latency < 0 {
			o = Observation{EndpointID: id, CheckedAt: now, Health: coreconfig.Health{Available: false, LastFailure: now}, Failure: "endpoint probe failed"}
		}
		observed[id] = o
	}
	c.apply.Lock()
	defer c.apply.Unlock()
	c.mu.Lock()
	if c.generation != generation {
		c.mu.Unlock()
		return errors.New("health generation superseded")
	}
	health := map[string]coreconfig.Health{}
	for _, id := range g.Members {
		o, ok := observed[id]
		old := c.observations[id]
		if !ok {
			o = Observation{EndpointID: id, CheckedAt: time.Now().UTC(), Health: coreconfig.Health{LastFailure: time.Now().UTC()}, Failure: "endpoint probe canceled"}
		}
		if o.Available && o.LastFailure.IsZero() {
			o.LastFailure = old.LastFailure
		}
		if !o.Available && o.LastSuccess.IsZero() {
			o.LastSuccess = old.LastSuccess
			o.Latency = old.Latency
		}
		c.observations[id] = o
		health[id] = o.Health
	}
	wasQuarantined := c.status.Quarantined
	c.mu.Unlock()
	selected, e := coreconfig.FallbackSelection(g, health, time.Now().UTC(), c.opts.MaxAge)
	if bounded.Err() != nil || e != nil {
		return c.closeGates(generation, "no healthy fallback member")
	}
	if selected == selection(g) && !wasQuarantined {
		c.mu.Lock()
		if c.generation != generation {
			c.mu.Unlock()
			return errors.New("health generation superseded")
		}
		c.status.State = "ready"
		c.status.Failure = ""
		c.mu.Unlock()
		return nil
	}
	next, e := m.Select(g.ID, selected)
	if e != nil {
		return c.closeGates(generation, "fallback selection invalid")
	}
	if c.opts.ApplyModel(bounded, next) != nil {
		return c.closeGates(generation, "fallback apply failed")
	}
	if bounded.Err() != nil {
		return c.closeGates(generation, "fallback apply canceled")
	}
	c.mu.Lock()
	if c.generation != generation {
		c.mu.Unlock()
		return c.closeGates(generation, "fallback generation superseded")
	}
	c.model = next
	for _, group := range next.Groups {
		if group.ID == g.ID {
			c.group = group
		}
	}
	c.status.Selected = selected
	c.status.State = "ready"
	c.status.Failure = ""
	c.status.Quarantined = false
	c.mu.Unlock()
	return nil
}
func (c *Controller) closeGates(generation uint64, code string) error {
	c.mu.Lock()
	current := c.generation == generation
	c.mu.Unlock()
	if !current {
		return errors.New("health generation superseded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.TickTimeout)
	defer cancel()
	if c.opts.Quarantine(ctx) != nil {
		code = "fallback quarantine failed"
	}
	c.mu.Lock()
	if c.generation == generation {
		c.status.State = "quarantined"
		c.status.Failure = code
		c.status.Quarantined = true
	}
	c.mu.Unlock()
	return errors.New(code)
}

// UpdateModel cancels stale observations and stages a replacement policy only
// after closing gates. The active selection changes only after a fresh Tick
// successfully commits ApplyModel; an unobserved replacement is never released.
func (c *Controller) UpdateModel(ctx context.Context, m coreconfig.Model) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return errors.New("health controller closed")
	}
	next, g, e := validated(m, c.opts.GroupID)
	if e != nil {
		return e
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("health controller closed")
	}
	c.generation++
	generation := c.generation
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.apply.Lock()
	defer c.apply.Unlock()
	c.mu.Lock()
	current := c.generation == generation
	c.mu.Unlock()
	if !current {
		return errors.New("model generation superseded")
	}
	bounded, cancel := context.WithTimeout(ctx, c.opts.TickTimeout)
	defer cancel()
	if c.opts.Quarantine(bounded) != nil {
		return c.closeGates(generation, "fallback quarantine failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return errors.New("model generation superseded")
	}
	c.model = next
	c.group = g
	keep := map[string]bool{}
	for _, id := range g.Members {
		keep[id] = true
	}
	for id := range c.observations {
		if !keep[id] {
			delete(c.observations, id)
		}
	}
	c.status.Generation = generation
	c.status.State = "unobserved"
	c.status.Failure = ""
	c.status.Quarantined = true
	return nil
}
func (c *Controller) Run(ctx context.Context, interval time.Duration) error {
	if interval < time.Second || interval > 24*time.Hour {
		return errors.New("invalid health interval")
	}
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return errors.New("health controller closed")
		}
		_ = c.Tick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		case <-c.closeDone:
			return errors.New("health controller closed")
		}
	}
}

// Close supersedes observations before closing gates. It serializes against
// apply; concurrent closes wait for the first close to finish.
func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		done := c.closeDone
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.closed = true
	c.generation++
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.apply.Lock()
	defer c.apply.Unlock()
	bounded, cancel := context.WithTimeout(ctx, c.opts.TickTimeout)
	defer cancel()
	err := c.opts.Quarantine(bounded)
	c.mu.Lock()
	c.status.State = "closed"
	c.status.Quarantined = true
	c.status.Generation = c.generation
	if err != nil {
		c.status.Failure = "fallback quarantine failed"
	}
	close(c.closeDone)
	c.mu.Unlock()
	if err != nil {
		return errors.New("fallback quarantine failed")
	}
	return nil
}
