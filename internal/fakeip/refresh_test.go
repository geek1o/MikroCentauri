//go:build linux || darwin

package fakeip

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type updateBackend struct {
	backendFuncs
	update func(context.Context, Mapping, Mapping) error
}

func (b updateBackend) Update(ctx context.Context, before, after Mapping) error {
	return b.update(ctx, before, after)
}

func TestRefreshKeepsAliasAndStableCandidate(t *testing.T) {
	c := fixtureConfig(t, 2)
	now := time.Unix(1000, 0)
	c.Now = func() time.Time { return now }
	candidates := []netip.Addr{address("10.77.0.20")}
	resolves, updates := 0, 0
	var installed Mapping
	r := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		resolves++
		return candidates, 5 * time.Second, nil
	})
	b := updateBackend{backendFuncs: backendFuncs{ensure: func(_ context.Context, m Mapping) error { installed = m; return nil }, verify: func(_ context.Context, m Mapping) error {
		if installed != m {
			return errors.New("wrong target")
		}
		return nil
	}}, update: func(_ context.Context, before, after Mapping) error {
		updates++
		pending := readJournal(t, c.Directory).Records[0]
		if pending.Ready || pending.PreviousMapping == nil || *pending.PreviousMapping != before || pending.Mapping != after {
			t.Fatal("target mutation preceded durable intent")
		}
		if installed != before {
			t.Fatal("wrong transition before")
		}
		installed = after
		return nil
	}}
	p := publisher(t, c, r, b)
	first, ttl, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.28"))
	if err != nil || ttl != 5*time.Second {
		t.Fatal(first, ttl, err)
	}
	now = now.Add(2 * time.Second)
	same, ttl, err := p.PublishAlias(context.Background(), "one.test", first.Fake)
	if err != nil || same != first || ttl != 3*time.Second || resolves != 1 {
		t.Fatal(same, ttl, err, resolves)
	}
	now = now.Add(3 * time.Second)
	candidates = []netip.Addr{address("10.77.0.19"), first.Real}
	if err := p.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.Mappings()[0] != first || updates != 0 || resolves != 2 {
		t.Fatal("current real candidate unnecessarily changed")
	}
	now = now.Add(5 * time.Second)
	candidates = []netip.Addr{address("10.77.0.22"), address("10.77.0.21")}
	changed, _, err := p.PublishAlias(context.Background(), "one.test", first.Fake)
	if err != nil || changed.Domain != first.Domain || changed.Fake != first.Fake || changed.Real != address("10.77.0.21") || updates != 1 {
		t.Fatal(changed, err, updates)
	}
	j := readJournal(t, c.Directory)
	if j.Version != 2 || !j.Records[0].Ready || j.Records[0].PreviousMapping != nil {
		t.Fatal("target commit not durable")
	}
	m, lease, err := p.PublishAlias(context.Background(), "two.test", first.Fake)
	noAnswer(t, m, lease, err)
}

func TestPendingTargetRestartRecoversBeforeResolving(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "before mutation", true: "lost reply"}[applied], func(t *testing.T) {
			c := fixtureConfig(t, 2)
			now := time.Unix(1000, 0)
			c.Now = func() time.Time { return now }
			target := address("10.77.0.20")
			var installed Mapping
			resolves := 0
			resolver := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
				resolves++
				return []netip.Addr{target}, 5 * time.Second, nil
			})
			b := updateBackend{backendFuncs: backendFuncs{ensure: func(_ context.Context, m Mapping) error { installed = m; return nil }}, update: func(_ context.Context, before, after Mapping) error {
				if applied {
					installed = after
				}
				return errors.New("interrupted")
			}}
			p := publisher(t, c, resolver, b)
			first, _, err := p.Publish(context.Background(), "one.test")
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(5 * time.Second)
			target = address("10.77.0.21")
			m, lease, err := p.Publish(context.Background(), "one.test")
			noAnswer(t, m, lease, err)
			pending := readJournal(t, c.Directory).Records[0]
			if pending.PreviousMapping == nil || pending.Ready {
				t.Fatal("interrupted transition not durable")
			}
			p.Close()
			target = address("10.77.0.22")
			recovered := false
			b.update = func(_ context.Context, before, after Mapping) error {
				if resolves != 2 || before != first || after.Real != address("10.77.0.21") || installed != before && installed != after {
					t.Fatal("resolved across pending intent or wrong recovery")
				}
				installed = after
				recovered = true
				return nil
			}
			b.verify = func(_ context.Context, m Mapping) error {
				if installed != m {
					return errors.New("wrong installed target")
				}
				return nil
			}
			// Deliberately fail the new resolution after recovery: the committed fallback
			// must remain the recovered target, while readiness and DNS fail closed.
			p = publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
				if !recovered {
					t.Fatal("resolve before pending recovery")
				}
				return nil, 0, errors.New("DNS outage")
			}), b)
			if err := p.Reconcile(context.Background()); err == nil {
				t.Fatal("expired DNS outage accepted")
			}
			j := readJournal(t, c.Directory).Records[0]
			if !j.Ready || j.PreviousMapping != nil || j.Mapping.Real != address("10.77.0.21") || j.Mapping.Fake != first.Fake {
				t.Fatal("failed refresh lost committed fallback")
			}
		})
	}
}

func TestRestartIgnoresPersistedFutureExpiryAndMigratesV1(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(map[int]string{1: "v1", 2: "v2"}[version], func(t *testing.T) {
			c := fixtureConfig(t, 2)
			p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
			first, _, err := p.Publish(context.Background(), "one.test")
			if err != nil {
				t.Fatal(err)
			}
			p.Close()
			j := readJournal(t, c.Directory)
			j.Version = version
			if version == 1 {
				j.Records[0].ExpiresAt = time.Time{}
			} else {
				j.Records[0].ExpiresAt = time.Unix(9999999999, 0)
			}
			data, _ := json.Marshal(j)
			if err := os.WriteFile(filepath.Join(c.Directory, "mappings.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			resolves := 0
			p = publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
				resolves++
				return fixtureResolver(context.Background(), "")
			}), backendFuncs{})
			same, _, err := p.Publish(context.Background(), "one.test")
			if err != nil || same != first || resolves != 1 || readJournal(t, c.Directory).Version != 2 {
				t.Fatal("restart trusted persisted lease or changed binding", same, err, resolves)
			}
		})
	}
}

func TestRefreshFailurePreservesFallbackAndLeaseNeverExtends(t *testing.T) {
	c := fixtureConfig(t, 2)
	now := time.Unix(1000, 0)
	c.Now = func() time.Time { return now }
	mode := "good"
	r := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		switch mode {
		case "outage":
			return nil, 0, errors.New("DNS unavailable")
		case "zero":
			return []netip.Addr{address("10.77.0.21")}, 0, nil
		case "subsecond":
			return []netip.Addr{address("10.77.0.21")}, time.Millisecond, nil
		case "slow":
			now = now.Add(5 * time.Second)
		}
		return []netip.Addr{address("10.77.0.20")}, 5 * time.Second, nil
	})
	p := publisher(t, c, r, backendFuncs{})
	first, _, err := p.Publish(context.Background(), "one.test")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	for _, failure := range []string{"outage", "zero", "subsecond", "slow"} {
		mode = failure
		m, ttl, err := p.Publish(context.Background(), "one.test")
		noAnswer(t, m, ttl, err)
		if p.Mappings()[0] != first || readJournal(t, c.Directory).Records[0].Mapping != first {
			t.Fatal("failed refresh changed fallback")
		}
	}
	mode = "good"
	p.backend = backendFuncs{verify: func(context.Context, Mapping) error { now = now.Add(5 * time.Second); return nil }}
	m, ttl, err := p.Publish(context.Background(), "one.test")
	noAnswer(t, m, ttl, err)
}

func TestRefreshRequiresUpdaterAndRejectsCorruptTransition(t *testing.T) {
	c := fixtureConfig(t, 2)
	now := time.Unix(1000, 0)
	c.Now = func() time.Time { return now }
	target := address("10.77.0.20")
	p := publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		return []netip.Addr{target}, 5 * time.Second, nil
	}), backendFuncs{})
	first, _, err := p.Publish(context.Background(), "one.test")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	target = address("10.77.0.21")
	m, ttl, err := p.Publish(context.Background(), "one.test")
	noAnswer(t, m, ttl, err)
	if p.Mappings()[0] != first {
		t.Fatal("unsupported update changed journal")
	}
	p.Close()
	j := readJournal(t, c.Directory)
	previous := first
	previous.Domain = "other.test"
	j.Records[0].PreviousMapping = &previous
	j.Records[0].Ready = false
	data, _ := json.Marshal(j)
	os.WriteFile(filepath.Join(c.Directory, "mappings.json"), data, 0600)
	if got, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
		got.Close()
		t.Fatal("changed domain in transition accepted")
	}
}
