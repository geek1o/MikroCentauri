// Package linuxbarrier implements a scoped Linux ingress policy barrier. It
// requires a dedicated table and priority and refuses foreign state before writes.
package linuxbarrier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/health"
)

type Native interface {
	Quarantine(context.Context) error
	Verify(context.Context) error
}
type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}
type execRunner struct{}

func (execRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "/sbin/ip", args...).Output()
}

type Options struct {
	Interface, TUN      string
	Table, RulePriority int
	// RouterOS container kernels place the standard local-table rule at 200;
	// ordinary Linux uses 0. This is an explicitly pinned platform input.
	LocalRulePriority int
	TUNPrefix         netip.Prefix
	Native            Native
	Canary            health.HTTPProbeConfig
	// IndependentCanary permits a dedicated literal-IP echo target whose route
	// is independent of the user's Active domain set. Actual egress must still
	// match Canary.ExpectedPeerIP; removing its proxy rule fails the probe.
	IndependentCanary bool
	Runner            Runner
	ReadForwarding    func() ([]byte, error)
}
type Barrier struct {
	mu         sync.Mutex
	options    Options
	probe      health.Checker
	canaryHost string
	verified   bool
}

var ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func New(o Options) (*Barrier, error) {
	if !ifacePattern.MatchString(o.Interface) || !ifacePattern.MatchString(o.TUN) || o.Interface == o.TUN || o.Table < 1 || o.Table >= 253 || o.RulePriority < 1 || o.RulePriority >= 32766 || o.LocalRulePriority < 0 || o.LocalRulePriority >= o.RulePriority || !o.TUNPrefix.IsValid() || !o.TUNPrefix.Addr().Is4() || o.Native == nil {
		return nil, errors.New("invalid scoped ingress barrier")
	}
	host, _, err := net.SplitHostPort(o.Canary.SOCKSAddress)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("canary requires private mixed endpoint")
	}
	u, err := url.Parse(o.Canary.URL)
	if err != nil {
		return nil, errors.New("invalid canary")
	}
	if o.IndependentCanary {
		address, err := netip.ParseAddr(u.Hostname())
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return nil, errors.New("independent canary requires literal IPv4 target")
		}
	}
	probe, err := health.NewHTTPProbe(o.Canary)
	if err != nil {
		return nil, err
	}
	if o.ReadForwarding == nil {
		o.ReadForwarding = func() ([]byte, error) { return os.ReadFile("/proc/sys/net/ipv4/ip_forward") }
	}
	if o.Runner == nil {
		o.Runner = execRunner{}
	}
	return &Barrier{options: o, probe: probe, canaryHost: u.Hostname()}, nil
}
func (b *Barrier) run(ctx context.Context, args ...string) (string, error) {
	out, err := b.options.Runner.Run(ctx, args...)
	if err != nil {
		return "", errors.New("Linux ingress command failed")
	}
	if len(out) > 65536 {
		return "", errors.New("Linux ingress readback oversized")
	}
	return strings.TrimSpace(string(out)), nil
}
func (b *Barrier) rule(ctx context.Context) (bool, error) {
	out, err := b.run(ctx, "rule", "show")
	if err != nil {
		return false, err
	}
	found := false
	localFound := false
	priority := strconv.Itoa(b.options.RulePriority) + ":"
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		number, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			return false, errors.New("invalid policy readback")
		}
		if fields[0] == priority {
			if found || strings.Join(fields[1:], " ") != "from all iif "+b.options.Interface+" lookup "+strconv.Itoa(b.options.Table) {
				return false, errors.New("foreign ingress priority")
			}
			found = true
		} else if number < b.options.RulePriority {
			if localFound || number != b.options.LocalRulePriority || strings.Join(fields[1:], " ") != "from all lookup local" {
				return false, errors.New("earlier policy can bypass ingress quarantine")
			}
			localFound = true
		}
	}
	if !localFound {
		return false, errors.New("pinned local policy rule absent")
	}
	return found, nil
}
func (b *Barrier) route(ctx context.Context) (string, error) {
	out, err := b.run(ctx, "route", "show", "table", strconv.Itoa(b.options.Table))
	if err != nil {
		return "", err
	}
	switch out {
	case "", "blackhole default", "blackhole default scope global", "default dev " + b.options.TUN + " scope link", "default dev " + b.options.TUN:
		return out, nil
	}
	return "", errors.New("foreign ingress table")
}
func (b *Barrier) closed(ctx context.Context) error {
	found, err := b.rule(ctx)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("ingress rule absent")
	}
	route, err := b.route(ctx)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(route, "blackhole default") {
		return errors.New("ingress is not quarantined")
	}
	return nil
}
func (b *Barrier) Quarantine(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.verified = false
	found, err := b.rule(ctx)
	if err != nil {
		return err
	}
	if _, err = b.route(ctx); err != nil {
		return err
	}
	if _, err = b.run(ctx, "route", "replace", "blackhole", "default", "table", strconv.Itoa(b.options.Table)); err != nil {
		return err
	}
	if !found {
		if _, err = b.run(ctx, "rule", "add", "priority", strconv.Itoa(b.options.RulePriority), "iif", b.options.Interface, "lookup", strconv.Itoa(b.options.Table)); err != nil {
			return err
		}
	}
	if err = b.closed(ctx); err != nil {
		return err
	}
	return b.options.Native.Quarantine(ctx)
}
func (b *Barrier) tun(ctx context.Context) error {
	forwarding, err := b.options.ReadForwarding()
	if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
		return errors.New("IPv4 forwarding disabled")
	}
	link, err := b.run(ctx, "-o", "link", "show", "dev", b.options.TUN)
	if err != nil {
		return err
	}
	start, end := strings.Index(link, "<"), strings.Index(link, ">")
	if start < 0 || end < start {
		return errors.New("invalid TUN link")
	}
	up := false
	for _, flag := range strings.Split(link[start+1:end], ",") {
		if flag == "UP" {
			up = true
		}
	}
	if !up {
		return errors.New("TUN down")
	}
	addresses, err := b.run(ctx, "-o", "-4", "addr", "show", "dev", b.options.TUN)
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(addresses, "\n") {
		fields := strings.Fields(line)
		for i, v := range fields {
			if v == "inet" && i+1 < len(fields) && fields[i+1] == b.options.TUNPrefix.String() {
				found = true
			}
		}
	}
	if !found {
		return errors.New("TUN address mismatch")
	}
	return nil
}
func (b *Barrier) Verify(ctx context.Context, m coreconfig.Model) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.verified = false
	selected := false
	for _, domain := range m.DNS.SelectedDomains {
		if domain == b.canaryHost {
			selected = true
		}
	}
	if !selected && !b.options.IndependentCanary {
		return errors.New("canary is outside selected namespace")
	}
	if err := b.closed(ctx); err != nil {
		return err
	}
	if err := b.tun(ctx); err != nil {
		return err
	}
	if err := b.options.Native.Verify(ctx); err != nil {
		return err
	}
	if err := b.probe.Check(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.verified = true
	return nil
}
func (b *Barrier) Release(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.verified {
		return errors.New("forwarding has not been verified")
	}
	b.verified = false
	if err := b.closed(ctx); err != nil {
		return err
	}
	if err := b.tun(ctx); err != nil {
		return err
	}
	if err := b.options.Native.Verify(ctx); err != nil {
		return err
	}
	if _, err := b.run(ctx, "route", "replace", "default", "dev", b.options.TUN, "table", strconv.Itoa(b.options.Table)); err != nil {
		return err
	}
	route, err := b.route(ctx)
	if err != nil || !strings.HasPrefix(route, "default dev "+b.options.TUN) || ctx.Err() != nil {
		// Restore only a positively recognized owned default. Unknown readback
		// may be a concurrent foreign edit and must remain untouched. Native
		// authority is still revoked and the caller must retain readiness DOWN.
		if err != nil {
			return errors.New("release readback unresolved; readiness must remain held")
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, restoreErr := b.run(cleanup, "route", "replace", "blackhole", "default", "table", strconv.Itoa(b.options.Table))
		return errors.Join(errors.New("release readback denied"), restoreErr)
	}
	return ctx.Err()
}
