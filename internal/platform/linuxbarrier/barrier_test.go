package linuxbarrier

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/health"
)

type fakeRunner struct {
	rules, route, link, address string
	commands                    []string
	badReadback                 bool
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	cmd := strings.Join(args, " ")
	f.commands = append(f.commands, cmd)
	switch cmd {
	case "rule show":
		return []byte(f.rules), nil
	case "route show table 100":
		return []byte(f.route), nil
	case "route replace blackhole default table 100":
		f.route = "blackhole default"
		return nil, nil
	case "rule add priority 10000 iif mc-probe lookup 100":
		f.rules += "\n10000: from all iif mc-probe lookup 100"
		return nil, nil
	case "route replace default dev mc-tun table 100":
		if f.badReadback {
			f.route = "foreign"
		} else {
			f.route = "default dev mc-tun scope link"
		}
		return nil, nil
	case "-o link show dev mc-tun":
		return []byte(f.link), nil
	case "-o -4 addr show dev mc-tun":
		return []byte(f.address), nil
	}
	return nil, errors.New("unexpected command")
}

type fakeNative struct {
	err    error
	closed *fakeRunner
	calls  []string
}

func (n *fakeNative) Quarantine(context.Context) error {
	n.calls = append(n.calls, "quarantine")
	if n.closed.route != "blackhole default" {
		return errors.New("native before ingress quarantine")
	}
	return n.err
}
func (n *fakeNative) Verify(context.Context) error { n.calls = append(n.calls, "verify"); return n.err }

type fakeProbe struct {
	err   error
	calls int
}

func (p *fakeProbe) Check(context.Context) error { p.calls++; return p.err }
func barrierFixture(t *testing.T) (*Barrier, *fakeRunner, *fakeNative, *fakeProbe) {
	t.Helper()
	r := &fakeRunner{rules: "0: from all lookup local\n32766: from all lookup main", link: "4: mc-tun: <POINTOPOINT,UP,LOWER_UP> mtu 1500", address: "4: mc-tun inet 172.31.255.1/30 scope global mc-tun"}
	n := &fakeNative{closed: r}
	b, err := New(Options{Interface: "mc-probe", TUN: "mc-tun", Table: 100, RulePriority: 10000, TUNPrefix: netip.MustParsePrefix("172.31.255.1/30"), Native: n, Runner: r, ReadForwarding: func() ([]byte, error) { return []byte("1\n"), nil }, Canary: health.HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://selected.test:8080/canary", ExpectedPeerIP: "10.77.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProbe{}
	b.probe = p
	return b, r, n, p
}
func model() coreconfig.Model {
	return coreconfig.Model{DNS: coreconfig.DNS{SelectedDomains: []string{"selected.test"}}}
}
func TestBarrierOrdersQuarantineVerificationAndRelease(t *testing.T) {
	b, r, n, p := barrierFixture(t)
	ctx := context.Background()
	if b.Release(ctx) == nil {
		t.Fatal("unverified release")
	}
	if err := b.Quarantine(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(ctx, model()); err != nil {
		t.Fatal(err)
	}
	if r.route != "blackhole default" || p.calls != 1 {
		t.Fatal("verification opened forwarding")
	}
	if err := b.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if r.route != "default dev mc-tun scope link" || strings.Join(n.calls, ",") != "quarantine,verify,verify" {
		t.Fatalf("wrong ordering %+v", n.calls)
	}
	if b.Release(ctx) == nil {
		t.Fatal("verification reused")
	}
}
func TestBarrierRefusesForeignPolicyBeforeMutation(t *testing.T) {
	for _, kind := range []string{"priority", "earlier", "table", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			b, r, _, _ := barrierFixture(t)
			switch kind {
			case "priority":
				r.rules += "\n10000: from all lookup 42"
			case "earlier":
				r.rules += "\n50: from all lookup 42"
			case "table":
				r.route = "192.0.2.0/24 via 10.0.0.1"
			case "duplicate":
				r.rules += "\n10000: from all iif mc-probe lookup 100\n10000: from all iif mc-probe lookup 100"
			}
			if b.Quarantine(context.Background()) == nil {
				t.Fatal("foreign state accepted")
			}
			for _, cmd := range r.commands {
				if strings.Contains(cmd, "replace") || strings.Contains(cmd, "add") {
					t.Fatal("mutated foreign policy")
				}
			}
		})
	}
}
func TestBarrierFailureRetainsQuarantine(t *testing.T) {
	for _, kind := range []string{"native", "canary", "tun", "selected", "release-readback", "forwarding"} {
		t.Run(kind, func(t *testing.T) {
			b, r, n, p := barrierFixture(t)
			ctx := context.Background()
			if err := b.Quarantine(ctx); err != nil {
				t.Fatal(err)
			}
			m := model()
			switch kind {
			case "native":
				n.err = errors.New("lease live")
			case "canary":
				p.err = errors.New("direct egress")
			case "tun":
				r.link = "4: mc-tun: <POINTOPOINT,LOWER_UP>"
			case "forwarding":
				b.options.ReadForwarding = func() ([]byte, error) { return []byte("0"), nil }
			case "selected":
				m.DNS.SelectedDomains = nil
			}
			err := b.Verify(ctx, m)
			if kind == "release-readback" {
				if err != nil {
					t.Fatal(err)
				}
				r.badReadback = true
				err = b.Release(ctx)
			}
			if err == nil {
				t.Fatal("fault accepted")
			}
			if kind == "release-readback" {
				if r.route != "foreign" {
					t.Fatal("unknown foreign readback overwritten")
				}
			} else if r.route != "blackhole default" {
				t.Fatal("failure opened forwarding")
			}
		})
	}
}
