package linuxbarrier

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func appKernelFixture() (AppKernelOptions, *fakeRunner, *string, *[]string) {
	r := &fakeRunner{rules: "200: from all lookup local\n32766: from all lookup main"}
	state := "0"
	writes := []string{}
	o := AppKernelOptions{Interface: "mc-probe", Table: 100, RulePriority: 10000, LocalRulePriority: 200, Runner: r,
		CheckIngress: func(name string) error {
			if name != "mc-probe" {
				return errors.New("foreign")
			}
			return nil
		},
		PrepareTUN:     func() error { return nil },
		ReadForwarding: func() ([]byte, error) { return []byte(state), nil },
		WriteForwarding: func(value []byte) error {
			if string(value) == "1\n" && (r.route != "blackhole default" || !strings.Contains(r.rules, "10000: from all iif mc-probe lookup 100")) {
				return errors.New("enabled before quarantine")
			}
			state = strings.TrimSpace(string(value))
			writes = append(writes, state)
			return nil
		},
	}
	return o, r, &state, &writes
}

func TestAppKernelQuarantineBeforeForwardingAndRestart(t *testing.T) {
	o, r, state, writes := appKernelFixture()
	restore, err := PrepareAppKernel(context.Background(), o)
	if err != nil || *state != "1" || len(*writes) != 1 {
		t.Fatal("startup", err, *state, *writes)
	}
	// A restart accepts only the exact existing rule and owned blackhole table.
	again, err := PrepareAppKernel(context.Background(), o)
	if err != nil {
		t.Fatal("restart", err)
	}
	if err := again(); err != nil || *state != "1" {
		t.Fatal("previously enabled forwarding changed", err)
	}
	if err := restore(); err != nil || *state != "0" || r.route != "blackhole default" {
		t.Fatal("restoration", err, *state, r.route)
	}
	if err := restore(); err != nil || len(*writes) != 2 {
		t.Fatal("cleanup not idempotent", err, *writes)
	}
}

func TestAppKernelRefusesForeignAuthorityAndUnavailableDevice(t *testing.T) {
	for name, mutate := range map[string]func(*AppKernelOptions, *fakeRunner){
		"foreign priority":  func(o *AppKernelOptions, r *fakeRunner) { r.rules += "\n10000: from all lookup main" },
		"foreign table":     func(o *AppKernelOptions, r *fakeRunner) { r.route = "default via 10.0.0.1 dev foreign" },
		"earlier bypass":    func(o *AppKernelOptions, r *fakeRunner) { r.rules += "\n100: from all lookup main" },
		"local rule absent": func(o *AppKernelOptions, r *fakeRunner) { r.rules = "32766: from all lookup main" },
		"interface absent": func(o *AppKernelOptions, r *fakeRunner) {
			o.CheckIngress = func(string) error { return errors.New("absent") }
		},
		"TUN absent":   func(o *AppKernelOptions, r *fakeRunner) { o.PrepareTUN = func() error { return errors.New("absent") } },
		"unsafe table": func(o *AppKernelOptions, r *fakeRunner) { o.Table = 254 },
		"unknown forwarding": func(o *AppKernelOptions, r *fakeRunner) {
			o.ReadForwarding = func() ([]byte, error) { return []byte("unknown"), nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			o, r, state, writes := appKernelFixture()
			mutate(&o, r)
			if _, err := PrepareAppKernel(context.Background(), o); err == nil || *state != "0" || len(*writes) != 0 {
				t.Fatal("unsafe startup", err, *state, *writes)
			}
			for _, cmd := range r.commands {
				if strings.Contains(cmd, "replace") || strings.Contains(cmd, " add ") {
					t.Fatal("mutated foreign authority", cmd)
				}
			}
		})
	}
}

func TestAppKernelForwardingFailureRestoresClosedState(t *testing.T) {
	o, r, state, writes := appKernelFixture()
	read := o.ReadForwarding
	failOnce := true
	o.ReadForwarding = func() ([]byte, error) {
		if *state == "1" && failOnce {
			failOnce = false
			return nil, errors.New("readback unavailable")
		}
		return read()
	}
	if _, err := PrepareAppKernel(context.Background(), o); err == nil || *state != "0" || r.route != "blackhole default" || len(*writes) != 2 {
		t.Fatal("failed activation escaped closure", err, *state, *writes)
	}
}
