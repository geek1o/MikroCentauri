package coreactivation

import (
	"context"
	"errors"
	"sync"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/supervisor"
)

// Managed composes actual fallback observations with the supervisor and finite
// publication adapter. One instance owns the complete lifecycle; callers must
// not independently mutate the namespace or invoke a second apply controller.
type Managed struct {
	op      sync.Mutex
	life    context.Context
	cancel  context.CancelFunc
	adapter *Adapter
	process *supervisor.Supervisor
	group   *grouphealth.Controller
}
type ManagedStatus struct {
	Ready   bool
	Process supervisor.Status
	Traffic Status
	Group   grouphealth.ControllerStatus
}
type ManagedOptions struct {
	Activation          Options
	Process             supervisor.Options
	Model               coreconfig.Model
	GroupID             string
	Probe               func(context.Context, endpoints.Endpoint) (grouphealth.Observation, error)
	MaxAge, TickTimeout time.Duration
}

func NewManaged(ctx context.Context, o ManagedOptions) (*Managed, error) {
	if o.Probe == nil {
		return nil, errors.New("managed core requires endpoint observations")
	}
	a, err := New(o.Activation)
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		bounded, cancel := context.WithTimeout(context.Background(), a.opts.Timeout)
		defer cancel()
		a.Close(bounded)
	}
	o.Process.Semantic = a.Semantic
	o.Process.Hooks = a.Hooks()
	s, err := supervisor.New(o.Process)
	if err != nil {
		cleanup()
		return nil, err
	}
	closeAll := func() {
		bounded, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.Close(bounded)
		a.Close(bounded)
	}
	if err = a.Prune(s.RetainedRevisions()); err != nil {
		closeAll()
		return nil, err
	}
	if _, err = a.Register(o.Model); err != nil {
		closeAll()
		return nil, err
	}
	// Existing LKG is durable state, not proof of current endpoint health.
	if err = s.Stop(ctx); err != nil {
		closeAll()
		return nil, err
	}
	c, err := grouphealth.New(grouphealth.Options{Model: o.Model, GroupID: o.GroupID, Probe: o.Probe, MaxAge: o.MaxAge, TickTimeout: o.TickTimeout, Quarantine: s.Stop, ApplyModel: func(ctx context.Context, m coreconfig.Model) error {
		b, err := a.Register(m)
		if err != nil {
			return err
		}
		return s.Apply(ctx, b)
	}})
	if err != nil {
		closeAll()
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	return &Managed{adapter: a, process: s, group: c, life: life, cancel: cancel}, nil
}
func (m *Managed) Tick(ctx context.Context) error {
	m.op.Lock()
	defer m.op.Unlock()
	if m.life.Err() != nil {
		return errors.New("managed core closed")
	}
	linked, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.life, cancel)
	defer stop()
	err := m.group.Tick(linked)
	if err == nil {
		if checkErr := m.adapter.Check(linked); checkErr != nil {
			err = errors.Join(checkErr, m.group.Invalidate())
		}
	}
	return errors.Join(err, m.adapter.Prune(m.process.RetainedRevisions()))
}
func (m *Managed) Run(ctx context.Context, interval time.Duration) error {
	if interval < time.Second || interval > 24*time.Hour {
		return errors.New("invalid health interval")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.life.Err() != nil {
			return errors.New("managed core closed")
		}
		_ = m.Tick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.life.Done():
			return errors.New("managed core closed")
		case <-ticker.C:
		}
	}
}
func (m *Managed) UpdateModel(ctx context.Context, model coreconfig.Model) error {
	m.op.Lock()
	defer m.op.Unlock()
	if m.life.Err() != nil {
		return errors.New("managed core closed")
	}
	return m.group.UpdateModel(ctx, model)
}
func (m *Managed) Status() ManagedStatus {
	s := ManagedStatus{Process: m.process.Status(), Traffic: m.adapter.Status(), Group: m.group.Status()}
	s.Ready = m.life.Err() == nil && s.Process.Live && s.Process.Ready && s.Traffic.Ready && s.Traffic.Admission.Admitted && !s.Group.Quarantined && s.Group.State == "ready"
	return s
}
func (m *Managed) Close(ctx context.Context) error {
	m.cancel()
	groupErr := m.group.Close(ctx)
	m.op.Lock()
	defer m.op.Unlock()
	return errors.Join(groupErr, m.process.Close(ctx), m.adapter.Close(ctx))
}
