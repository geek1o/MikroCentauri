package linuxbarrier

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

// AppKernelOptions pins the dedicated network namespace's ingress authority.
// Injected hooks are for acceptance tests; production uses fixed kernel paths.
type AppKernelOptions struct {
	Interface                              string
	Table, RulePriority, LocalRulePriority int
	Runner                                 Runner
	CheckIngress                           func(string) error
	PrepareTUN                             func() error
	ReadForwarding                         func() ([]byte, error)
	WriteForwarding                        func([]byte) error
}

type appKernelNative struct{}

func (appKernelNative) Quarantine(context.Context) error { return nil }
func (appKernelNative) Verify(context.Context) error {
	return errors.New("kernel preparation cannot admit traffic")
}

// PrepareAppKernel closes scoped Linux ingress before enabling forwarding.
// It never creates a TUN interface or grants native readiness. Its cleanup
// restores initially disabled forwarding, after the caller shuts down its owner.
// Existing matching policy is accepted on restart; foreign policy is refused.
func PrepareAppKernel(ctx context.Context, o AppKernelOptions) (func() error, error) {
	if !ifacePattern.MatchString(o.Interface) || o.Interface == "mc-tun" || o.Table < 1 || o.Table >= 253 || o.RulePriority < 1 || o.RulePriority >= 32766 || o.LocalRulePriority < 0 || o.LocalRulePriority >= o.RulePriority {
		return nil, errors.New("invalid App kernel ingress authority")
	}
	if o.CheckIngress == nil {
		o.CheckIngress = func(name string) error { _, err := net.InterfaceByName(name); return err }
	}
	if o.PrepareTUN == nil {
		o.PrepareTUN = prepareAppTUN
	}
	if o.ReadForwarding == nil {
		o.ReadForwarding = func() ([]byte, error) { return os.ReadFile("/proc/sys/net/ipv4/ip_forward") }
	}
	if o.WriteForwarding == nil {
		o.WriteForwarding = func(value []byte) error { return os.WriteFile("/proc/sys/net/ipv4/ip_forward", value, 0600) }
	}
	if o.Runner == nil {
		o.Runner = execRunner{}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if o.CheckIngress(o.Interface) != nil {
		return nil, errors.New("App ingress interface unavailable")
	}
	if o.PrepareTUN() != nil {
		return nil, errors.New("App TUN device unavailable; verify staged container privilege")
	}
	initial, err := o.ReadForwarding()
	if err != nil || (strings.TrimSpace(string(initial)) != "0" && strings.TrimSpace(string(initial)) != "1") {
		return nil, errors.New("App forwarding state unavailable")
	}
	b := &Barrier{options: Options{Interface: o.Interface, TUN: "mc-tun", Table: o.Table, RulePriority: o.RulePriority, LocalRulePriority: o.LocalRulePriority, Runner: o.Runner, Native: appKernelNative{}}}
	if err := b.Quarantine(ctx); err != nil {
		return nil, err
	}
	changed := strings.TrimSpace(string(initial)) == "0"
	var once sync.Once
	var cleanupError error
	cleanup := func() error {
		once.Do(func() {
			if !changed {
				return
			}
			if o.WriteForwarding([]byte("0\n")) != nil {
				cleanupError = errors.New("App forwarding restoration failed")
				return
			}
			value, err := o.ReadForwarding()
			if err != nil || strings.TrimSpace(string(value)) != "0" {
				cleanupError = errors.New("App forwarding restoration readback failed")
			}
		})
		return cleanupError
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if changed {
		if o.WriteForwarding([]byte("1\n")) != nil {
			return nil, errors.Join(errors.New("App forwarding enable failed"), cleanup())
		}
	}
	value, err := o.ReadForwarding()
	if err != nil || strings.TrimSpace(string(value)) != "1" {
		return nil, errors.Join(errors.New("App forwarding enable readback failed"), cleanup())
	}
	return cleanup, nil
}
