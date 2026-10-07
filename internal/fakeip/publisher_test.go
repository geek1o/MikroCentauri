//go:build linux || darwin

package fakeip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]netip.Addr, time.Duration, error)

func (f resolverFunc) ResolveA(ctx context.Context, domain string) ([]netip.Addr, time.Duration, error) {
	return f(ctx, domain)
}

type backendFuncs struct {
	ensure func(context.Context, Mapping) error
	verify func(context.Context, Mapping) error
}

func (b backendFuncs) Ensure(ctx context.Context, m Mapping) error {
	if b.ensure != nil {
		return b.ensure(ctx, m)
	}
	return nil
}
func (b backendFuncs) Verify(ctx context.Context, m Mapping) error {
	if b.verify != nil {
		return b.verify(ctx, m)
	}
	return nil
}
func address(s string) netip.Addr { return netip.MustParseAddr(s) }
func fixtureResolver(context.Context, string) ([]netip.Addr, time.Duration, error) {
	return []netip.Addr{address("10.77.0.20")}, time.Minute, nil
}
func fixtureConfig(t *testing.T, capacity uint32) Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Directory: directory, Capacity: capacity, Now: func() time.Time { return time.Unix(1000, 0) }}
}
func publisher(t *testing.T, c Config, r Resolver, b Backend) *Publisher {
	t.Helper()
	p, err := New(c, r, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}
func readJournal(t *testing.T, directory string) journal {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, "mappings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	return j
}
func noAnswer(t *testing.T, m Mapping, ttl time.Duration, err error) {
	t.Helper()
	if err == nil || m != (Mapping{}) || ttl != 0 {
		t.Fatalf("expected no published answer; got %+v %s %v", m, ttl, err)
	}
}

func TestPublicationBarrierAndPinning(t *testing.T) {
	c := fixtureConfig(t, 4)
	var events []string
	resolves := 0
	r := resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		resolves++
		return []netip.Addr{address("10.77.0.21"), address("2001:db8::1"), address("10.77.0.20")}, time.Minute, nil
	})
	b := backendFuncs{ensure: func(_ context.Context, m Mapping) error {
		events = append(events, "ensure")
		j := readJournal(t, c.Directory)
		if len(j.Records) != 1 || j.Records[0].Mapping != m || j.Records[0].Ready {
			t.Fatal("reservation not durable before backend mutation")
		}
		return nil
	}, verify: func(_ context.Context, m Mapping) error {
		events = append(events, "verify")
		if readJournal(t, c.Directory).Records[0].Ready {
			t.Fatal("marked ready before verification")
		}
		return nil
	}}
	p := publisher(t, c, r, b)
	m, ttl, err := p.Publish(context.Background(), "SELECTED.Test.")
	if err != nil {
		t.Fatal(err)
	}
	if m.Domain != "selected.test" || m.Fake != address("198.18.0.1") || m.Real != address("10.77.0.20") || ttl != MaxTTL || strings.Join(events, ",") != "ensure,verify" {
		t.Fatalf("unexpected publication %+v %s %v", m, ttl, events)
	}
	if !readJournal(t, c.Directory).Records[0].Ready {
		t.Fatal("ready not durable at return")
	}
	p.backend = backendFuncs{verify: func(context.Context, Mapping) error { events = append(events, "again"); return nil }}
	second, _, err := p.Publish(context.Background(), "selected.test")
	if err != nil || second != m || resolves != 1 || events[len(events)-1] != "again" {
		t.Fatal("mapping not pinned or backend verification omitted")
	}
	for _, name := range []string{"publisher.lock", "mappings.json"} {
		info, err := os.Stat(filepath.Join(c.Directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private mode: %s %v", name, err)
		}
	}
}

func TestFailureThenRestartResumesReservationWithoutReuse(t *testing.T) {
	c := fixtureConfig(t, 3)
	lostReply := errors.New("lost reply after mutation")
	var written Mapping
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{ensure: func(_ context.Context, m Mapping) error { written = m; return lostReply }})
	m, ttl, err := p.Publish(context.Background(), "first.test")
	noAnswer(t, m, ttl, err)
	if readJournal(t, c.Directory).Records[0].Ready {
		t.Fatal("failed mapping published")
	}
	p.Close()
	calls := 0
	p = publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) {
		calls++
		return fixtureResolver(context.Background(), "")
	}), backendFuncs{})
	second, _, err := p.Publish(context.Background(), "second.test")
	if err != nil || second.Fake != address("198.18.0.2") {
		t.Fatalf("failed reservation reused: %+v %v", second, err)
	}
	resumed, _, err := p.Publish(context.Background(), "first.test")
	if err != nil || resumed != written || calls != 2 {
		t.Fatalf("pending reservation did not resume: %+v %v resolves=%d", resumed, err, calls)
	}
}

func TestVerifyFailureAndReadyControlOutage(t *testing.T) {
	c := fixtureConfig(t, 2)
	offline := errors.New("control disconnected")
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{verify: func(context.Context, Mapping) error { return offline }})
	m, ttl, err := p.Publish(context.Background(), "selected.test")
	noAnswer(t, m, ttl, err)
	p.backend = backendFuncs{}
	if _, _, err := p.Publish(context.Background(), "selected.test"); err != nil {
		t.Fatal(err)
	}
	p.backend = backendFuncs{verify: func(context.Context, Mapping) error { return offline }}
	m, ttl, err = p.Publish(context.Background(), "selected.test")
	noAnswer(t, m, ttl, err)
}

func TestDiskWriteFailureBeforeBackend(t *testing.T) {
	c := fixtureConfig(t, 2)
	calls := 0
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{ensure: func(context.Context, Mapping) error { calls++; return nil }})
	if err := os.Mkdir(filepath.Join(c.Directory, "mappings.json"), 0700); err != nil {
		t.Fatal(err)
	}
	m, ttl, err := p.Publish(context.Background(), "selected.test")
	noAnswer(t, m, ttl, err)
	if calls != 0 {
		t.Fatal("backend called before successful durable reservation")
	}
	if err := os.Remove(filepath.Join(c.Directory, "mappings.json")); err != nil {
		t.Fatal(err)
	}
	m, ttl, err = p.Publish(context.Background(), "other.test")
	noAnswer(t, m, ttl, err)
}

func TestDiskWriteFailureAfterVerification(t *testing.T) {
	c := fixtureConfig(t, 2)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{verify: func(context.Context, Mapping) error {
		if err := os.Remove(filepath.Join(c.Directory, "mappings.json")); err != nil {
			t.Fatal(err)
		}
		return os.Mkdir(filepath.Join(c.Directory, "mappings.json"), 0700)
	}})
	m, ttl, err := p.Publish(context.Background(), "selected.test")
	noAnswer(t, m, ttl, err)
}

func TestAliasBindingsSurviveRestartAndAllocatorSkips(t *testing.T) {
	c := fixtureConfig(t, 4)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	first, _, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	p = publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	same, _, err := p.PublishAlias(context.Background(), "ONE.TEST.", first.Fake)
	if err != nil || same != first {
		t.Fatal("alias binding lost on restart")
	}
	m, ttl, err := p.PublishAlias(context.Background(), "two.test", first.Fake)
	noAnswer(t, m, ttl, err)
	m, ttl, err = p.PublishAlias(context.Background(), "one.test", address("198.18.0.9"))
	noAnswer(t, m, ttl, err)
	m, ttl, err = p.PublishAlias(context.Background(), "other.test", address("10.77.0.20"))
	noAnswer(t, m, ttl, err)
	second, _, err := p.Publish(context.Background(), "two.test")
	if err != nil || second.Fake != address("198.18.0.2") {
		t.Fatal("allocator reused engine alias")
	}
}

func TestPendingAliasCannotBeReassigned(t *testing.T) {
	c := fixtureConfig(t, 2)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{ensure: func(context.Context, Mapping) error { return errors.New("failure") }})
	m, ttl, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.27"))
	noAnswer(t, m, ttl, err)
	p.Close()
	p = publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	m, ttl, err = p.PublishAlias(context.Background(), "two.test", address("198.18.0.27"))
	noAnswer(t, m, ttl, err)
	resumed, _, err := p.PublishAlias(context.Background(), "one.test", address("198.18.0.27"))
	if err != nil || resumed.Fake != address("198.18.0.27") {
		t.Fatal("cannot resume pending alias")
	}
}

func TestCapacityConcurrencyAndCancellation(t *testing.T) {
	c := fixtureConfig(t, 2)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var mappings []Mapping
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, _, err := p.Publish(context.Background(), "same.test")
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			mappings = append(mappings, m)
			mu.Unlock()
		}()
	}
	wg.Wait()
	for _, m := range mappings {
		if m != mappings[0] {
			t.Fatal("concurrent allocation not serialized")
		}
	}
	if len(readJournal(t, c.Directory).Records) != 1 {
		t.Fatal("duplicate concurrent reservations")
	}
	if _, _, err := p.Publish(context.Background(), "second.test"); err != nil {
		t.Fatal(err)
	}
	m, ttl, err := p.Publish(context.Background(), "third.test")
	noAnswer(t, m, ttl, err)
	if !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, ttl, err = p.Publish(ctx, "same.test")
	noAnswer(t, m, ttl, err)
	p.Close()
	m, ttl, err = p.Publish(context.Background(), "same.test")
	noAnswer(t, m, ttl, err)
	if !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestCancellationDuringVerifyDoesNotPublish(t *testing.T) {
	c := fixtureConfig(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{verify: func(context.Context, Mapping) error { cancel(); return nil }})
	m, ttl, err := p.Publish(ctx, "selected.test")
	noAnswer(t, m, ttl, err)
	if readJournal(t, c.Directory).Records[0].Ready {
		t.Fatal("canceled verification published")
	}
}

func TestStrictJournalAndSingleWriter(t *testing.T) {
	c := fixtureConfig(t, 2)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{})
	if _, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
		t.Fatal("second writer acquired journal")
	}
	if _, _, err := p.Publish(context.Background(), "one.test"); err != nil {
		t.Fatal(err)
	}
	p.Close()
	original, _ := os.ReadFile(filepath.Join(c.Directory, "mappings.json"))
	cases := map[string][]byte{"unknown": []byte(strings.Replace(string(original), `"version":2`, `"version":2,"password":"secret"`, 1)), "duplicate JSON key": []byte(strings.Replace(string(original), `"version":2`, `"version":9,"version":2`, 1)), "trailing": append(append([]byte{}, original...), []byte(` {}`)...), "invalid alias": []byte(strings.Replace(string(original), "198.18.0.1", "203.0.113.1", 1))}
	var j journal
	json.Unmarshal(original, &j)
	j.Records = append(j.Records, j.Records[0])
	cases["duplicate mapping"], _ = json.Marshal(j)
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(c.Directory, "mappings.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
				got.Close()
				t.Fatal("corrupt journal accepted")
			}
		})
	}
	if err := os.WriteFile(filepath.Join(c.Directory, "mappings.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(c.Directory, "mappings.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
		got.Close()
		t.Fatal("public journal accepted")
	}
}

func TestDomainAndResolverRestrictions(t *testing.T) {
	for _, name := range []string{"", "a..test", "a.test..", "*.test", "-a.test", "a-.test", " a.test", "домен.test", "a_test", strings.Repeat("x", 64) + ".test"} {
		if _, err := CanonicalDomain(name); err == nil {
			t.Fatalf("invalid name %q accepted", name)
		}
	}
	for i, addresses := range [][]netip.Addr{{address("2001:db8::1")}, {address("198.18.0.2")}, {address("0.0.0.0")}, {address("224.0.0.1")}, {}} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c := fixtureConfig(t, 2)
			p := publisher(t, c, resolverFunc(func(context.Context, string) ([]netip.Addr, time.Duration, error) { return addresses, time.Second, nil }), backendFuncs{})
			m, ttl, err := p.Publish(context.Background(), "one.test")
			noAnswer(t, m, ttl, err)
			if _, err := os.Stat(filepath.Join(c.Directory, "mappings.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid answer reserved an alias")
			}
		})
	}
}

func TestReconcilePendingAndReadyReservations(t *testing.T) {
	c := fixtureConfig(t, 4)
	p := publisher(t, c, resolverFunc(fixtureResolver), backendFuncs{ensure: func(context.Context, Mapping) error { return errors.New("offline") }})
	_, _, _ = p.PublishAlias(context.Background(), "one.test", address("198.18.0.25"))
	_, _, _ = p.PublishAlias(context.Background(), "two.test", address("198.18.0.29"))
	mappings := p.Mappings()
	if len(mappings) != 2 {
		t.Fatal("pending snapshot incomplete")
	}
	mappings[0].Domain = "mutated.test"
	if p.Mappings()[0].Domain != "one.test" {
		t.Fatal("snapshot modifies reservations")
	}
	var events []string
	p.backend = backendFuncs{ensure: func(_ context.Context, m Mapping) error { events = append(events, "ensure:"+m.Domain); return nil }, verify: func(_ context.Context, m Mapping) error { events = append(events, "verify:"+m.Domain); return nil }}
	if err := p.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "ensure:one.test,verify:one.test,ensure:two.test,verify:two.test" {
		t.Fatalf("reconcile order %v", events)
	}
	for _, r := range readJournal(t, c.Directory).Records {
		if !r.Ready {
			t.Fatal("pending reconciliation not durable")
		}
	}
	events = nil
	if err := p.Reconcile(context.Background()); err != nil || len(events) != 4 {
		t.Fatal("ready records bypass fresh verification")
	}
	p.backend = backendFuncs{verify: func(context.Context, Mapping) error { return errors.New("disconnected") }}
	if err := p.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile accepted stale local ready records")
	}
	p.Close()
	if !errors.Is(p.Reconcile(context.Background()), ErrClosed) {
		t.Fatal("reconcile accepted closed publisher")
	}
}

func TestConfigurationAndSymlinkValidation(t *testing.T) {
	for _, c := range []Config{{Capacity: 1}, {Directory: t.TempDir(), Capacity: 4097}, {Directory: t.TempDir(), Capacity: 1, Prefix: netip.MustParsePrefix("203.0.113.0/24")}, {Directory: t.TempDir(), Capacity: 2, Prefix: netip.MustParsePrefix("198.18.0.0/31")}, {Directory: t.TempDir(), Capacity: 1, Prefix: netip.MustParsePrefix("198.18.0.1/24")}} {
		if p, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
			p.Close()
			t.Fatalf("invalid config accepted %+v", c)
		}
	}
	c := fixtureConfig(t, 2)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(c.Directory, "mappings.json")); err != nil {
		t.Fatal(err)
	}
	if p, err := New(c, resolverFunc(fixtureResolver), backendFuncs{}); err == nil {
		p.Close()
		t.Fatal("symlink journal accepted")
	}
}
