package dnsgate

import (
	"context"
	"mikrocentauri.local/core/internal/fakeip"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetiredDNSBypassesFakeIPAllocator(t *testing.T) {
	var internalCalls, realCalls, publicationCalls atomic.Int32
	internal := upstream(t, func(req []byte) []byte { internalCalls.Add(1); return goodReply(req) })
	real := upstream(t, func(req []byte) []byte {
		realCalls.Add(1)
		q, err := parse(req, 4096)
		if err != nil || q.questions[0].name != "retired.test" {
			t.Errorf("unexpected real query: %v", err)
		}
		// Require canonical wire names even for retired queries; the engine's
		// historical case-sensitive cache must never see these new questions.
		if string(req) != string(query("retired.test", 1)) {
			t.Error("retired query was not canonicalized")
		}
		return response(req, q.questions[0], []byte{10, 77, 0, 20}, 30)
	})
	g, err := New(Config{InternalAddress: internal, Selected: []string{"selected.test"}, Retired: []string{"retired.test"}, RealAddress: real}, publisherFunc(func(c context.Context, name string, alias netip.Addr) (fakeip.Mapping, time.Duration, error) {
		publicationCalls.Add(1)
		return successfulPublisher(c, name, alias)
	}))
	if err != nil {
		t.Fatal(err)
	}
	answer := g.Handle(context.Background(), query("ReTiReD.TeSt", 1))
	parsed, err := parse(answer, 4096)
	if err != nil || len(parsed.answers) != 1 || string(parsed.answers[0].data) != string([]byte{10, 77, 0, 20}) {
		t.Fatalf("real response missing: %x %v", answer, err)
	}
	if internalCalls.Load() != 0 || publicationCalls.Load() != 0 || realCalls.Load() != 1 {
		t.Fatal("retired query reached allocator or publisher")
	}
	g.Handle(context.Background(), query("selected.test", 1))
	if internalCalls.Load() != 1 || publicationCalls.Load() != 1 || realCalls.Load() != 1 {
		t.Fatal("active query bypassed publication")
	}
}

func TestRetiredRealDNSRejectsAliasLeak(t *testing.T) {
	g, err := New(Config{InternalAddress: "127.0.0.1:5354", Retired: []string{"selected.test"}, RealAddress: upstream(t, goodReply)}, publisherFunc(successfulPublisher))
	if err != nil {
		t.Fatal(err)
	}
	assertFailure(t, g.Handle(context.Background(), query("selected.test", 1)))
}

func TestMalformedRetirementPolicy(t *testing.T) {
	for _, modify := range []func(*Config){
		func(c *Config) { c.RealAddress = "" },
		func(c *Config) { c.RealAddress = "198.18.0.3:53" },
		func(c *Config) { c.RealAddress = "resolver.test:53" },
		func(c *Config) { c.RealAddress = "10.77.0.20:0" },
		func(c *Config) { c.RealAddress = "10.77.0.20:65536" },
		func(c *Config) { c.RealAddress = c.InternalAddress },
		func(c *Config) { c.Retired = []string{"SELECTED.test."} },
		func(c *Config) { c.Retired = []string{"retired.test", "Retired.test."} },
		func(c *Config) { c.Selected = []string{"selected.test", "Selected.test."} },
	} {
		cfg := Config{InternalAddress: "127.0.0.1:5354", Selected: []string{"selected.test"}, Retired: []string{"retired.test"}, RealAddress: "10.77.0.20:53"}
		modify(&cfg)
		if _, err := New(cfg, publisherFunc(successfulPublisher)); err == nil {
			t.Fatalf("accepted malformed policy: %+v", cfg)
		}
	}
}
