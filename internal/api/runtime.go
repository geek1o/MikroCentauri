package api

import (
	"context"
	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
)

type RuntimeView struct {
	Revision uint64 `json:"revision"`
	Ready    bool   `json:"ready"`
	Pending  bool   `json:"pending"`
}
type Runtime interface {
	View() RuntimeView
	Model() (coreconfig.Model, error)
	Validate(context.Context, uint64, coreconfig.Model) error
	Apply(context.Context, uint64, coreconfig.Model) error
}
type CoreRuntime struct{ Core *coreactivation.Transition }

func (r CoreRuntime) View() RuntimeView {
	s := r.Core.Status()
	return RuntimeView{s.Namespace.Revision, s.Ready, s.Namespace.Pending != nil}
}
func (r CoreRuntime) Model() (coreconfig.Model, error) { return r.Core.CurrentModel() }
func (r CoreRuntime) Validate(ctx context.Context, rev uint64, m coreconfig.Model) error {
	return r.Core.ValidateModel(ctx, rev, m)
}
func (r CoreRuntime) Apply(ctx context.Context, rev uint64, m coreconfig.Model) error {
	_, e := r.Core.Apply(ctx, rev, m.DNS.SelectedDomains, m)
	return e
}

// PreparedRuntime binds application plans to the resolved generated candidate.
type PreparedRuntime interface {
	Runtime
	CandidateFingerprint(context.Context, uint64, coreconfig.Model) (string, error)
	ApplyPrepared(context.Context, uint64, coreconfig.Model, string) error
}

func (r CoreRuntime) CandidateFingerprint(ctx context.Context, rev uint64, m coreconfig.Model) (string, error) {
	return r.Core.CandidateFingerprint(ctx, rev, m)
}
func (r CoreRuntime) ApplyPrepared(ctx context.Context, rev uint64, m coreconfig.Model, fp string) error {
	_, e := r.Core.ApplyPrepared(ctx, rev, m.DNS.SelectedDomains, m, fp)
	return e
}
