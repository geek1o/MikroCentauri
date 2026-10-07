package coreactivation

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/namespace"
	"mikrocentauri.local/core/internal/supervisor"
)

// Deterministic child fixture creates only cache metadata, not an engine DB.
// Alias and backend behavior below are fault-injected dependencies, not CHR.
func init() {
	if len(os.Args) == 4 && os.Args[1] == "run" && os.Args[2] == "-c" {
		b, err := os.ReadFile(os.Args[3])
		if err != nil {
			os.Exit(2)
		}
		var cfg struct {
			Experimental struct {
				Cache struct {
					Path string `json:"path"`
				} `json:"cache_file"`
			} `json:"experimental"`
		}
		if json.Unmarshal(b, &cfg) != nil {
			os.Exit(2)
		}
		if _, err = os.Stat(cfg.Experimental.Cache.Path); os.IsNotExist(err) {
			if os.WriteFile(cfg.Experimental.Cache.Path, []byte("fixture-cache-metadata"), 0600) != nil {
				os.Exit(2)
			}
		}
		for {
			time.Sleep(time.Second)
		}
	}
}

type ledgerFixture struct {
	mu           sync.Mutex
	mappings     []fakeip.Mapping
	fail         atomic.Bool
	expireOnce   atomic.Bool
	expireAlways atomic.Bool
	calls        atomic.Int32
}

func (l *ledgerFixture) Mappings() []fakeip.Mapping {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]fakeip.Mapping{}, l.mappings...)
}
func (l *ledgerFixture) PublishAlias(ctx context.Context, n string, ip netip.Addr) (fakeip.Mapping, time.Duration, error) {
	l.calls.Add(1)
	if l.expireOnce.Swap(false) || l.expireAlways.Load() {
		return fakeip.Mapping{}, 0, fakeip.ErrLeaseExpiredDuringVerification
	}
	if l.fail.Load() {
		return fakeip.Mapping{}, 0, errors.New("fixture REST outage with secret")
	}
	if err := ctx.Err(); err != nil {
		return fakeip.Mapping{}, 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.mappings {
		if m.Domain == n {
			if m.Fake != ip {
				return fakeip.Mapping{}, 0, errors.New("alias changed")
			}
			return m, time.Minute, nil
		}
	}
	m := fakeip.Mapping{Domain: n, Fake: ip, Real: netip.MustParseAddr("203.0.113.10")}
	l.mappings = append(l.mappings, m)
	return m, time.Minute, nil
}

type engineFixture struct {
	changed atomic.Bool
	calls   atomic.Int32
}

func (e *engineFixture) Alias(ctx context.Context, n string) (netip.Addr, error) {
	e.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if e.changed.Load() {
		return netip.MustParseAddr("198.18.0.99"), nil
	}
	if n == "selected.test" {
		return netip.MustParseAddr("198.18.0.2"), nil
	}
	return netip.MustParseAddr("198.18.0.3"), nil
}

type barrierFixture struct {
	quarantined atomic.Bool
	releases    atomic.Int32
	failVerify  atomic.Bool
	checkCommit func() error
}

func (b *barrierFixture) Quarantine(context.Context) error { b.quarantined.Store(true); return nil }
func (b *barrierFixture) Verify(context.Context, coreconfig.Model) error {
	if !b.quarantined.Load() || b.failVerify.Load() {
		return errors.New("fixture readiness denied")
	}
	return nil
}
func (b *barrierFixture) Release(context.Context) error {
	if b.checkCommit != nil {
		if e := b.checkCommit(); e != nil {
			return e
		}
	}
	b.releases.Add(1)
	b.quarantined.Store(false)
	return nil
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	return dir
}
func fixtureModel(t *testing.T) coreconfig.Model {
	t.Helper()
	ep, e := endpoints.ParseURI("ss://aes-256-gcm:public-fixture@127.0.0.1:8388#fixture")
	if e != nil {
		t.Fatal(e)
	}
	return coreconfig.Model{SchemaVersion: 2, Instance: "bridge", Mode: "hybrid", Endpoints: []endpoints.Endpoint{ep}, Groups: []coreconfig.Group{{ID: "manual", Type: "selector", Members: []string{ep.ID}}}, DefaultOutbound: "manual", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", SelectedDomains: []string{"selected.test"}, CachePath: "/data/singbox-cache.db"}}
}
func setup(t *testing.T) (Options, *namespace.Store, *ledgerFixture, *engineFixture, *barrierFixture) {
	t.Helper()
	store, e := namespace.New(namespace.Config{Directory: privateDir(t), Initial: []string{"selected.test", "retired.test"}, Capacity: 32})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.Prepare(1, []string{"selected.test"}); e != nil {
		t.Fatal(e)
	}
	if _, e = store.Commit(2); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	l, engine, barrier := &ledgerFixture{}, &engineFixture{}, &barrierFixture{}
	o := Options{Directory: privateDir(t), Namespace: store, Ledger: l, Engine: engine, Barrier: barrier, Ports: coreconfig.Options{DNSPort: 15353, MixedPort: 12080}, RealDNSAddress: "127.0.0.1:15354", Timeout: time.Second}
	return o, store, l, engine, barrier
}
func newSupervisor(t *testing.T, a *Adapter, dir string) *supervisor.Supervisor {
	t.Helper()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	s, e := supervisor.New(supervisor.Options{Binary: binary, Directory: dir, Semantic: a.Semantic, Hooks: a.Hooks(), Validator: func(context.Context, string) error { return nil }, ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond, CrashLimit: 2})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSupervisorBridgeCommitRestartAndRollback(t *testing.T) {
	o, _, ledger, _, barrier := setup(t)
	a, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	dir := privateDir(t)
	barrier.checkCommit = func() error {
		b, e := os.ReadFile(filepath.Join(dir, "journal.json"))
		var j struct {
			Active  string `json:"active"`
			Pending string `json:"pending"`
		}
		if e != nil || json.Unmarshal(b, &j) != nil || j.Active == "" || j.Pending != "" {
			return errors.New("forwarding preceded config commit")
		}
		return nil
	}
	s := newSupervisor(t, a, dir)
	b, e := a.Register(fixtureModel(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if !s.Status().Ready || !a.Status().Ready || barrier.quarantined.Load() || len(ledger.Mappings()) != 2 || ledger.calls.Load() < 4 {
		t.Fatal("core bridge did not complete fresh admission and commit")
	}
	old := s.Status()
	bad := append(append([]byte{}, b...), []byte(" ")...)
	if e = s.Apply(context.Background(), bad); e == nil || s.Status().PID != old.PID {
		t.Fatal("unregistered candidate disturbed active child")
	}
	model := fixtureModel(t)
	model.Instance = "replacement"
	replacement, e := a.Register(model)
	if e != nil {
		t.Fatal(e)
	}
	ledger.fail.Store(true)
	if e = s.Apply(context.Background(), replacement); e == nil {
		t.Fatal("backend failure activated candidate")
	}
	if s.Status().Ready || a.Status().Ready || !barrier.quarantined.Load() {
		t.Fatal("backend failure left publication open")
	}
	ledger.fail.Store(false)
	if e = s.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	if s.Status().Revision != old.Revision || !s.Status().Ready {
		t.Fatal("LKG recovery did not restore registered model")
	}
	if e = s.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = a.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	a, e = New(o)
	if e != nil {
		t.Fatal(e)
	}
	s = newSupervisor(t, a, dir)
	defer func() { s.Close(context.Background()); a.Close(context.Background()) }()
	if e = s.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !a.Status().Ready || s.Status().Revision != old.Revision {
		t.Fatal("reopened bridge lost model registry")
	}
}
func TestAliasMismatchCacheLossAndNamespaceDrift(t *testing.T) {
	o, store, ledger, engine, barrier := setup(t)
	a, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	s := newSupervisor(t, a, privateDir(t))
	defer func() { s.Close(context.Background()); a.Close(context.Background()) }()
	b, e := a.Register(fixtureModel(t))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Apply(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(context.Background()); e != nil {
		t.Fatal(e)
	}
	engine.changed.Store(true)
	calls := ledger.calls.Load()
	if e = s.Start(context.Background()); e == nil || ledger.calls.Load() != calls || !barrier.quarantined.Load() {
		t.Fatal("foreign alias passed admission or mutated backend")
	}
	engine.changed.Store(false)
	if e = os.Remove(a.CachePath()); e != nil {
		t.Fatal(e)
	}
	engineCalls := engine.calls.Load()
	if e = s.Start(context.Background()); e == nil || engine.calls.Load() != engineCalls {
		t.Fatal("missing reserved cache reached allocator")
	}
	if _, e = store.Prepare(2, []string{"retired.test"}); e != nil {
		t.Fatal(e)
	}
	if _, e = store.Commit(3); e != nil {
		t.Fatal(e)
	}
	if e = a.Semantic(b); e == nil {
		t.Fatal("out-of-band namespace change accepted")
	}
}
func TestHeldGateAndRegistryPrivacy(t *testing.T) {
	o, _, _, engine, _ := setup(t)
	a, e := New(o)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close(context.Background())
	if _, e = New(o); e == nil {
		t.Fatal("duplicate registry owner")
	}
	request := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 8, 's', 'e', 'l', 'e', 'c', 't', 'e', 'd', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	answer := a.Handler().Handle(context.Background(), request)
	if len(answer) < 12 || binary.BigEndian.Uint16(answer[6:8]) != 0 || engine.calls.Load() != 0 {
		t.Fatal("held DNS gate called allocator or released alias")
	}
	b, e := a.Register(fixtureModel(t))
	if e != nil {
		t.Fatal(e)
	}
	path := a.modelPath(digest(b))
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("public model")
	}
	if e = os.WriteFile(path, []byte(`{"schema_version":2,"schema_version":2}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = a.Semantic(b); e == nil {
		t.Fatal("duplicate registered JSON accepted")
	}
}

func TestRuntimeCheckStagesQuarantineWithoutPrivateErrors(t *testing.T) {
	for _, stage := range []string{"cache", "allocator", "publication"} {
		t.Run(stage, func(t *testing.T) {
			o, _, ledger, engine, barrier := setup(t)
			a, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			s := newSupervisor(t, a, privateDir(t))
			defer func() { s.Close(context.Background()); a.Close(context.Background()) }()
			b, err := a.Register(fixtureModel(t))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Apply(context.Background(), b); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "cache":
				if err = os.Chmod(a.CachePath(), 0644); err != nil {
					t.Fatal(err)
				}
			case "allocator":
				engine.changed.Store(true)
			case "publication":
				ledger.fail.Store(true)
			}
			err = a.Check(context.Background())
			if err == nil || RuntimeCheckEvent(err) != "core_"+stage+"_check_failed" || !barrier.quarantined.Load() || a.Status().Ready {
				t.Fatalf("verification did not classify and quarantine: %v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), a.CachePath()) {
				t.Fatal("private failure leaked")
			}
		})
	}
	if RuntimeCheckEvent(errors.New("credential-bearing error")) != "core_check_failed" {
		t.Fatal("raw error projected")
	}
}

func TestRuntimeCheckLeaseRefreshIsPrivateAndBounded(t *testing.T) {
	for _, mode := range []string{"once", "always", "backend"} {
		t.Run(mode, func(t *testing.T) {
			o, _, ledger, _, barrier := setup(t)
			a, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			s := newSupervisor(t, a, privateDir(t))
			defer func() { s.Close(context.Background()); a.Close(context.Background()) }()
			b, err := a.Register(fixtureModel(t))
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Apply(context.Background(), b); err != nil {
				t.Fatal(err)
			}
			bindings := len(a.Status().Admission.Bindings)
			before := ledger.calls.Load()
			switch mode {
			case "once":
				ledger.expireOnce.Store(true)
			case "always":
				ledger.expireAlways.Store(true)
			case "backend":
				ledger.fail.Store(true)
			}
			err = a.Check(context.Background())
			calls := ledger.calls.Load() - before
			if mode == "once" {
				if err != nil || calls != int32(bindings+1) || !a.Status().Ready || barrier.quarantined.Load() || a.Status().LeaseRefreshRetries != 1 {
					t.Fatalf("fresh private proof was not admitted: %v calls=%d", err, calls)
				}
			} else {
				want := int32(2)
				if mode == "backend" {
					want = 1
				}
				if err == nil || calls != want || a.Status().Ready || !barrier.quarantined.Load() {
					t.Fatalf("failure retried or admitted: %v calls=%d", err, calls)
				}
			}
		})
	}
}
