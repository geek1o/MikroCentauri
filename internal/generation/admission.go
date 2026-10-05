//go:build linux || darwin

// Package generation admits a finite FakeIP namespace without recycling aliases.
package generation

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

var ErrDenied = errors.New("FakeIP generation not admitted")

type Engine interface {
	Alias(context.Context, string) (netip.Addr, error)
}
type Ledger interface {
	Mappings() []fakeip.Mapping
	PublishAlias(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error)
}
type Config struct {
	Selected []string
	Prefix   netip.Prefix
	Capacity uint32
}
type Binding struct {
	Domain string     `json:"domain"`
	Alias  netip.Addr `json:"alias"`
}
type Snapshot struct {
	Admitted bool      `json:"admitted"`
	Reason   string    `json:"reason"`
	Epoch    uint64    `json:"epoch"`
	Bindings []Binding `json:"bindings"`
}
type Admission struct {
	mu       sync.Mutex
	config   Config
	engine   Engine
	ledger   Ledger
	epoch    uint64
	reason   string
	receipt  map[string]netip.Addr
	lifetime context.Context
	cancel   context.CancelFunc
}

func New(config Config, engine Engine, ledger Ledger) (*Admission, error) {
	pool := netip.MustParsePrefix("198.18.0.0/15")
	if !config.Prefix.IsValid() {
		config.Prefix = pool
	}
	if engine == nil || ledger == nil || config.Capacity < 1 || config.Capacity > 4096 || len(config.Selected) < 1 || len(config.Selected) > int(config.Capacity) {
		return nil, errors.New("finite selected namespace and dependencies required")
	}
	if !config.Prefix.Addr().Is4() || config.Prefix != config.Prefix.Masked() || config.Prefix.Bits() < 15 || !pool.Contains(config.Prefix.Addr()) {
		return nil, errors.New("invalid FakeIP prefix")
	}
	if uint64(config.Capacity) >= uint64(1)<<uint(32-config.Prefix.Bits()) {
		return nil, errors.New("capacity exceeds prefix")
	}
	config.Selected = append([]string(nil), config.Selected...)
	seen := make(map[string]bool)
	for i, name := range config.Selected {
		canonical, err := fakeip.CanonicalDomain(name)
		if err != nil || seen[canonical] {
			return nil, errors.New("invalid or duplicate selected domain")
		}
		seen[canonical] = true
		config.Selected[i] = canonical
	}
	return &Admission{config: config, engine: engine, ledger: ledger, reason: "not_admitted"}, nil
}

// Revoke invalidates receipts immediately and cancels operations from that epoch.
// Network implementations must honor cancellation; their durable reservations
// may remain, but no result from the revoked epoch can be released to a client.
func (a *Admission) Revoke() { a.mu.Lock(); defer a.mu.Unlock(); a.revokeLocked("revoked") }
func (a *Admission) revokeLocked(reason string) {
	if a.cancel != nil {
		a.cancel()
	}
	a.epoch++
	a.receipt = nil
	a.reason = reason
}
func (a *Admission) fail(epoch uint64, reason string, err error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.epoch == epoch {
		a.revokeLocked(reason)
	}
	return err
}
func (a *Admission) current(epoch uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.epoch == epoch
}

// Admit seeds engine aliases in configured order. Every alias and existing
// ledger binding is checked before the first publication mutation occurs.
func (a *Admission) Admit(ctx context.Context) error {
	a.mu.Lock()
	a.revokeLocked("admitting")
	epoch := a.epoch
	lifetime, cancel := context.WithCancel(context.Background())
	a.lifetime, a.cancel = lifetime, cancel
	a.mu.Unlock()
	op, stop := linkedContext(ctx, lifetime)
	defer stop()
	receipt := make(map[string]netip.Addr)
	aliases := make(map[netip.Addr]bool)
	for _, domain := range a.config.Selected {
		alias, err := a.engine.Alias(op, domain)
		if err != nil {
			return a.fail(epoch, "engine_error", err)
		}
		if err := operationError(ctx, op); err != nil {
			return a.fail(epoch, "cancelled", err)
		}
		if !alias.Is4() || !a.config.Prefix.Contains(alias) || aliases[alias] {
			return a.fail(epoch, "invalid_alias", ErrDenied)
		}
		aliases[alias] = true
		receipt[domain] = alias
	}
	seen := make(map[string]bool)
	for _, mapping := range a.ledger.Mappings() {
		if seen[mapping.Domain] || receipt[mapping.Domain] != mapping.Fake {
			return a.fail(epoch, "ledger_mismatch", ErrDenied)
		}
		seen[mapping.Domain] = true
	}
	for _, domain := range a.config.Selected {
		if err := operationError(ctx, op); err != nil {
			return a.fail(epoch, "cancelled", err)
		}
		if !a.current(epoch) {
			return ErrDenied
		}
		mapping, ttl, err := a.ledger.PublishAlias(op, domain, receipt[domain])
		if err != nil {
			return a.fail(epoch, "publication_error", err)
		}
		if mapping.Domain != domain || mapping.Fake != receipt[domain] || ttl <= 0 {
			return a.fail(epoch, "publication_mismatch", ErrDenied)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.epoch != epoch {
		return ErrDenied
	}
	if err := operationError(ctx, op); err != nil {
		a.revokeLocked("cancelled")
		return err
	}
	a.receipt = receipt
	a.reason = "admitted"
	return nil
}

func operationError(parent, operation context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	return operation.Err()
}

func linkedContext(parent, lifetime context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(lifetime)
	stop := context.AfterFunc(parent, cancel)
	if parent.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

// Begin guards an engine DNS exchange before it can allocate an alias. Its
// context belongs to the admitted epoch and is cancelled immediately on Revoke.
// The caller must use this context for the exchange and invoke the cleanup.
func (a *Admission) Begin(ctx context.Context, domain string) (context.Context, context.CancelFunc, error) {
	canonical, err := fakeip.CanonicalDomain(domain)
	if err != nil {
		return nil, nil, ErrDenied
	}
	a.mu.Lock()
	if a.receipt == nil {
		a.mu.Unlock()
		return nil, nil, ErrDenied
	}
	if _, ok := a.receipt[canonical]; !ok {
		a.mu.Unlock()
		return nil, nil, ErrDenied
	}
	lifetime := a.lifetime
	a.mu.Unlock()
	op, cancel := linkedContext(ctx, lifetime)
	if err := operationError(ctx, op); err != nil {
		cancel()
		return nil, nil, err
	}
	return op, cancel, nil
}

// Validate checks the engine's entire admitted namespace. Ingress must be
// quarantined before starting a replacement engine: a DNS query can allocate.
func (a *Admission) Validate(ctx context.Context) error {
	a.mu.Lock()
	if a.receipt == nil {
		a.mu.Unlock()
		return ErrDenied
	}
	epoch, lifetime := a.epoch, a.lifetime
	receipt := make(map[string]netip.Addr, len(a.receipt))
	for name, alias := range a.receipt {
		receipt[name] = alias
	}
	a.mu.Unlock()
	op, stop := linkedContext(ctx, lifetime)
	defer stop()
	for _, domain := range a.config.Selected {
		alias, err := a.engine.Alias(op, domain)
		if err != nil {
			return a.fail(epoch, "engine_error", err)
		}
		if alias != receipt[domain] {
			return a.fail(epoch, "engine_mismatch", ErrDenied)
		}
		if err := operationError(ctx, op); err != nil {
			return a.fail(epoch, "cancelled", err)
		}
	}
	if !a.current(epoch) {
		return ErrDenied
	}
	return nil
}

// PublishAlias implements the DNS gate publisher using the frozen admission.
func (a *Admission) PublishAlias(ctx context.Context, domain string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
	canonical, err := fakeip.CanonicalDomain(domain)
	if err != nil {
		return fakeip.Mapping{}, 0, ErrDenied
	}
	a.mu.Lock()
	if a.receipt == nil || a.receipt[canonical] != alias {
		a.mu.Unlock()
		return fakeip.Mapping{}, 0, ErrDenied
	}
	epoch, lifetime := a.epoch, a.lifetime
	a.mu.Unlock()
	op, stop := linkedContext(ctx, lifetime)
	defer stop()
	mapping, ttl, err := a.ledger.PublishAlias(op, canonical, alias)
	if err != nil {
		return fakeip.Mapping{}, 0, err
	}
	if err := operationError(ctx, op); err != nil {
		return fakeip.Mapping{}, 0, err
	}
	if !a.current(epoch) {
		return fakeip.Mapping{}, 0, ErrDenied
	}
	if mapping.Domain != canonical || mapping.Fake != alias || ttl <= 0 {
		return fakeip.Mapping{}, 0, a.fail(epoch, "publication_mismatch", ErrDenied)
	}
	return mapping, ttl, nil
}

func (a *Admission) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Admitted: a.receipt != nil, Reason: a.reason, Epoch: a.epoch}
	for _, domain := range a.config.Selected {
		if alias, ok := a.receipt[domain]; ok {
			s.Bindings = append(s.Bindings, Binding{Domain: domain, Alias: alias})
		}
	}
	return s
}
