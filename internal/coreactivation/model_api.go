package coreactivation

import (
	"context"
	"errors"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/namespace"
)

// CurrentModel is private controller state; HTTP callers must project secrets out.
func (t *Transition) CurrentModel() (coreconfig.Model, error) {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return coreconfig.Model{}, errors.New("transition unavailable")
	}
	s, e := t.options.Store.Snapshot()
	if e != nil {
		return coreconfig.Model{}, e
	}
	return t.load(committedView(s))
}

// ValidateModel performs read-only namespace preview and actual engine preflight.
// It does not reserve a namespace revision, register a model, or quarantine traffic.
func (t *Transition) ValidateModel(ctx context.Context, rev uint64, m coreconfig.Model) error {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return errors.New("transition unavailable")
	}
	s, e := t.options.Store.Preview(rev, m.DNS.SelectedDomains)
	if e != nil {
		return e
	}
	desired := namespace.Snapshot{Revision: s.Pending.Revision, Known: s.Pending.Known, Active: s.Pending.Active}
	ports, e := t.ports(ctx, m)
	if e != nil {
		return e
	}
	b, e := coreconfig.GenerateForNamespace(m, desired, ports)
	if e != nil {
		return e
	}
	return t.checkCandidate(ctx, b)
}
