// Package activation coordinates durable policy intent with fail-closed runtime
// barriers. Runtime adapters must own their resources and serialize all other
// lifecycle operations with this controller; the namespace store has one writer.
package activation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"mikrocentauri.local/core/internal/namespace"
)

// Runtime methods must be repeatable after process death. Quarantine closes DNS,
// revokes admission, stops the engine gracefully and confirms the native UP lease
// is absent. Validate checks the current configuration before interrupting it.
// Stage accepts only the committed or pending configuration. Verify proves all
// reserved alias bindings and their native mappings before Commit. Release opens
// TUN/DNS readiness only after Commit; native UP remains gated by its observer.
// Adapters must honor context deadlines and must not mutate policy snapshots.
type Runtime interface {
	Validate(context.Context, namespace.Snapshot) error
	Quarantine(context.Context) error
	Stage(context.Context, namespace.Snapshot) error
	Verify(context.Context, namespace.Snapshot) error
	Release(context.Context, namespace.Snapshot) error
}

type Controller struct {
	mu             sync.Mutex
	store          *namespace.Store
	runtime        Runtime
	cleanupTimeout time.Duration
}

func New(store *namespace.Store, runtime Runtime) (*Controller, error) {
	if store == nil || runtime == nil {
		return nil, errors.New("activation requires store and runtime")
	}
	return &Controller{store: store, runtime: runtime, cleanupTimeout: 10 * time.Second}, nil
}

// Apply rejects invalid or stale candidates before disturbing a healthy runtime.
// Once quarantine starts, every failure attempts quarantine again using a fresh
// bounded context. A pending candidate is retained for deterministic recovery.
func (c *Controller) Apply(ctx context.Context, revision uint64, active []string) (namespace.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	candidate, err := c.store.Preview(revision, active)
	if err != nil {
		return namespace.Snapshot{}, err
	}
	current, err := c.store.Snapshot()
	if err != nil {
		return namespace.Snapshot{}, err
	}
	if err = c.runtime.Validate(ctx, current); err != nil {
		return namespace.Snapshot{}, fmt.Errorf("validate committed policy: %w", err)
	}
	// Copy the preview's canonical active set before any runtime callback.
	wanted := append([]string{}, candidate.Pending.Active...)
	return c.guarded(ctx, func() (namespace.Snapshot, error) {
		if err := c.runtime.Quarantine(ctx); err != nil {
			return namespace.Snapshot{}, fmt.Errorf("quarantine: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return namespace.Snapshot{}, err
		}
		pending, err := c.store.Prepare(revision, wanted)
		if err != nil {
			return namespace.Snapshot{}, err
		}
		return c.activate(ctx, pending)
	})
}

// Recover is a synchronous startup operation. It replays pending intent, or
// revalidates the committed generation if death occurred after Commit and before
// Release. It never aborts reservations or releases traffic based on disk alone.
func (c *Controller) Recover(ctx context.Context) (namespace.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.guarded(ctx, func() (namespace.Snapshot, error) {
		if err := c.runtime.Quarantine(ctx); err != nil {
			return namespace.Snapshot{}, fmt.Errorf("quarantine: %w", err)
		}
		s, err := c.store.Snapshot()
		if err != nil {
			return namespace.Snapshot{}, err
		}
		return c.activate(ctx, s)
	})
}

func (c *Controller) activate(ctx context.Context, s namespace.Snapshot) (namespace.Snapshot, error) {
	desired := s
	if s.Pending != nil {
		desired = namespace.Snapshot{Revision: s.Pending.Revision, Known: append([]string{}, s.Pending.Known...), Active: append([]string{}, s.Pending.Active...)}
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	if err := c.runtime.Stage(ctx, clone(desired)); err != nil {
		return namespace.Snapshot{}, fmt.Errorf("stage: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	if err := c.runtime.Verify(ctx, clone(desired)); err != nil {
		return namespace.Snapshot{}, fmt.Errorf("verify: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	if s.Pending != nil {
		var err error
		s, err = c.store.Commit(s.Pending.Revision)
		if err != nil {
			return namespace.Snapshot{}, fmt.Errorf("commit: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	if err := c.runtime.Release(ctx, clone(s)); err != nil {
		return namespace.Snapshot{}, fmt.Errorf("release: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return namespace.Snapshot{}, err
	}
	return s, nil
}

func (c *Controller) guarded(ctx context.Context, run func() (namespace.Snapshot, error)) (namespace.Snapshot, error) {
	s, err := run()
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cleanupTimeout)
		defer cancel()
		if e := c.runtime.Quarantine(cleanup); e != nil {
			err = errors.Join(err, fmt.Errorf("cleanup quarantine failed: %w", e))
		}
	}
	return s, err
}

func clone(s namespace.Snapshot) namespace.Snapshot {
	s.Known = append([]string{}, s.Known...)
	s.Active = append([]string{}, s.Active...)
	if s.Pending != nil {
		p := *s.Pending
		p.Known = append([]string{}, p.Known...)
		p.Active = append([]string{}, p.Active...)
		s.Pending = &p
	}
	return s
}
