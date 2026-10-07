//go:build linux || darwin

package fakeip

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestReconcileRefreshesLeaseAfterVerificationCrossesFloor(t *testing.T) {
	c := fixtureConfig(t, 2)
	now := time.Unix(1000, 0)
	c.Now = func() time.Time { return now }
	resolves, verifies, ensures := 0, 0, 0
	var verifyDelay time.Duration
	var freshOrigin time.Time
	r := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		resolves++
		freshOrigin = now
		return []netip.Addr{address("10.77.0.20")}, 5 * time.Second, nil
	})
	b := backendFuncs{
		ensure: func(context.Context, Mapping) error { ensures++; return nil },
		verify: func(context.Context, Mapping) error { verifies++; now = now.Add(verifyDelay); return nil },
	}
	p := publisher(t, c, r, b)
	first, _, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.28"))
	if err != nil {
		t.Fatal(err)
	}
	oldDeadline := p.state.Records[0].deadline
	now = now.Add(3900 * time.Millisecond)
	verifyDelay = 200 * time.Millisecond
	if err = p.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resolves != 2 || verifies != 3 || ensures != 3 {
		t.Fatal("missing fresh resolution and verification", resolves, verifies, ensures)
	}
	if p.Mappings()[0] != first || !p.state.Records[0].deadline.Equal(freshOrigin.Add(5*time.Second)) || !p.state.Records[0].deadline.After(oldDeadline) {
		t.Fatal("binding changed or deadline did not use fresh DNS origin")
	}
	if got := p.remaining(p.state.Records[0]); got != 4*time.Second {
		t.Fatal("old TTL was extended", got)
	}
	if deadline := readJournal(t, c.Directory).Records[0].ExpiresAt; !deadline.Equal(freshOrigin.Add(5 * time.Second)) {
		t.Fatal("fresh lease not durable", deadline)
	}
}

func TestReconcileLeaseRetryBoundedAndErrorSpecific(t *testing.T) {
	for _, mode := range []string{"repeated_expiry", "verify_failure", "ensure_failure", "resolve_failure", "cancel_verification", "cancel_fresh_resolution"} {
		t.Run(mode, func(t *testing.T) {
			c := fixtureConfig(t, 2)
			now := time.Unix(1000, 0)
			c.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resolves, verifies, ensures := 0, 0, 0
			armed := false
			cause := errors.New("fixture boundary failure")
			r := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
				resolves++
				if armed && mode == "resolve_failure" {
					return nil, 0, cause
				}
				if armed && mode == "cancel_fresh_resolution" {
					cancel()
				}
				return []netip.Addr{address("10.77.0.20")}, 5 * time.Second, nil
			})
			b := backendFuncs{
				ensure: func(context.Context, Mapping) error {
					ensures++
					if armed && mode == "ensure_failure" {
						return cause
					}
					return nil
				},
				verify: func(context.Context, Mapping) error {
					verifies++
					if !armed {
						return nil
					}
					if mode == "verify_failure" {
						return cause
					}
					if mode == "cancel_verification" {
						cancel()
					}
					if verifies == 1 {
						now = now.Add(200 * time.Millisecond)
					} else {
						now = now.Add(5 * time.Second)
					}
					return nil
				},
			}
			p := publisher(t, c, r, b)
			if _, _, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.28")); err != nil {
				t.Fatal(err)
			}
			resolves, verifies, ensures = 0, 0, 0
			armed = true
			now = now.Add(3900 * time.Millisecond)
			if mode == "resolve_failure" {
				now = now.Add(2 * time.Second)
			}
			err := p.Reconcile(ctx)
			switch mode {
			case "repeated_expiry":
				if !errors.Is(err, ErrLeaseExpiredDuringVerification) || resolves != 1 || verifies != 2 || ensures != 2 {
					t.Fatal("retry was not bounded", err, resolves, verifies, ensures)
				}
			case "verify_failure":
				if !errors.Is(err, cause) || resolves != 0 || verifies != 1 || ensures != 1 {
					t.Fatal("verification error retried", err, resolves, verifies, ensures)
				}
			case "ensure_failure":
				if !errors.Is(err, cause) || resolves != 0 || verifies != 0 || ensures != 1 {
					t.Fatal("ensure error retried", err, resolves, verifies, ensures)
				}
			case "resolve_failure":
				if !errors.Is(err, cause) || resolves != 1 || verifies != 0 || ensures != 0 {
					t.Fatal("resolution error retried", err, resolves, verifies, ensures)
				}
			case "cancel_verification":
				if !errors.Is(err, context.Canceled) || resolves != 0 || verifies != 1 || ensures != 1 {
					t.Fatal("canceled operation retried", err, resolves, verifies, ensures)
				}
			case "cancel_fresh_resolution":
				if !errors.Is(err, context.Canceled) || resolves != 1 || verifies != 1 || ensures != 1 {
					t.Fatal("canceled fresh lease verified", err, resolves, verifies, ensures)
				}
			}
		})
	}
}

func TestPublishAliasStillDeniesLeaseExpiredDuringVerification(t *testing.T) {
	c := fixtureConfig(t, 2)
	now := time.Unix(1000, 0)
	c.Now = func() time.Time { return now }
	resolves, verifies := 0, 0
	armed := false
	p := publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		resolves++
		return []netip.Addr{address("10.77.0.20")}, 5 * time.Second, nil
	}), backendFuncs{verify: func(context.Context, Mapping) error {
		verifies++
		if armed {
			now = now.Add(200 * time.Millisecond)
		}
		return nil
	}})
	first, _, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.28"))
	if err != nil {
		t.Fatal(err)
	}
	oldDeadline := p.state.Records[0].deadline
	armed = true
	now = now.Add(3900 * time.Millisecond)
	m, ttl, err := p.PublishAlias(context.Background(), "one.test", first.Fake)
	noAnswer(t, m, ttl, err)
	if !errors.Is(err, ErrLeaseExpiredDuringVerification) || resolves != 1 || verifies != 2 || !p.state.Records[0].deadline.Equal(oldDeadline) {
		t.Fatal("public answer auto-refreshed expired receipt", err, resolves, verifies)
	}
}
