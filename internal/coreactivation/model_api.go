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

// ErrCandidateChanged means a reviewed candidate no longer matches its sources.
var ErrCandidateChanged = errors.New("reviewed core candidate changed")

func (t *Transition) CandidateFingerprint(ctx context.Context, rev uint64, m coreconfig.Model) (string, error) {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return "", errors.New("transition unavailable")
	}
	_, _, data, e := t.candidate(ctx, rev, m.DNS.SelectedDomains, m)
	if e != nil {
		return "", e
	}
	return digest(data), nil
}
func (t *Transition) candidate(ctx context.Context, rev uint64, active []string, m coreconfig.Model) (namespace.Snapshot, coreconfig.Options, []byte, error) {
	s, e := t.options.Store.Preview(rev, active)
	if e != nil {
		return namespace.Snapshot{}, coreconfig.Options{}, nil, e
	}
	desired := namespace.Snapshot{Revision: s.Pending.Revision, Known: s.Pending.Known, Active: s.Pending.Active}
	ports, e := t.ports(ctx, m)
	if e != nil {
		return desired, ports, nil, e
	}
	data, e := coreconfig.GenerateForNamespace(m, desired, ports)
	return desired, ports, data, e
}

// ApplyPrepared compares and freezes the resolved artifacts under the same
// owner lock. The resolver is invoked once; refresh cannot change an approved
// candidate between comparison and source-envelope pinning.
func (t *Transition) ApplyPrepared(ctx context.Context, rev uint64, active []string, m coreconfig.Model, fingerprint string) (namespace.Snapshot, error) {
	t.op.Lock()
	defer t.op.Unlock()
	if t.closed || t.poisoned {
		return namespace.Snapshot{}, errors.New("transition unavailable")
	}
	if e := ctx.Err(); e != nil {
		return namespace.Snapshot{}, e
	}
	desired, ports, data, e := t.candidate(ctx, rev, active, m)
	if e != nil {
		return namespace.Snapshot{}, e
	}
	if len(fingerprint) != 64 || digest(data) != fingerprint {
		return namespace.Snapshot{}, ErrCandidateChanged
	}
	if e = t.saveResolved(ctx, desired, m, ports); e != nil {
		return namespace.Snapshot{}, errors.Join(e, t.prune())
	}
	t.transitioning.Store(true)
	defer t.transitioning.Store(false)
	result, e := t.controller.Apply(ctx, rev, active)
	return result, errors.Join(e, t.prune())
}
