//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/engineguard"
	"mikrocentauri.local/core/internal/namespace"
)

// gatewayActivation is a disposable-lab adapter. Every entry is called while
// lifecycleMu is held, including startup recovery, HTTP controls and health.
// The controller is the sole namespace writer; the adapter never commits it.
type gatewayActivation struct{}

func (gatewayActivation) Validate(ctx context.Context, s namespace.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := os.ReadFile("/data/singbox.json")
	if err != nil {
		return err
	}
	return engineguard.Validate(data, engineguard.Config{Selected: s.Known, Active: s.Active})
}

func (gatewayActivation) Quarantine(ctx context.Context) error {
	// Attempt both barriers even if the Linux barrier or graceful stop fails.
	// A bounded cleanup context is supplied separately by the controller.
	stopErr := stopLockedContext(ctx)
	leaseCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	leaseErr := revokeNativeLease(leaseCtx)
	return errors.Join(stopErr, leaseErr)
}

func (gatewayActivation) Stage(ctx context.Context, s namespace.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rewritePolicy(s.Known, s.Active); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := installPolicy(s.Known, s.Active); err != nil {
		return err
	}
	fmt.Printf("activation stage revision=%d dns=held ingress=quarantined\n", s.Revision)
	return ctx.Err()
}

func (gatewayActivation) Verify(ctx context.Context, s namespace.Snapshot) error {
	if err := startEngineLocked(ctx); err != nil {
		return err
	}
	fmt.Printf("activation verified revision=%d dns=held ingress=quarantined\n", s.Revision)
	return activationFault("after-verify")
}

func (gatewayActivation) Release(ctx context.Context, s namespace.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Printf("activation committed revision=%d dns=held ingress=quarantined\n", s.Revision)
	if err := activationFault("before-release"); err != nil {
		return err
	}
	if err := releaseLocked(ctx); err != nil {
		return err
	}
	fmt.Printf("activation released revision=%d native-up=observer-gated\n", s.Revision)
	return nil
}

// Fixed-path process-death injection for the explicit disposable fixture only.
// No HTTP API arms it. Consume and sync the marker before exit so restart can
// recover the same revision without repeatedly injecting the same failure.
func activationFault(boundary string) error {
	if os.Getenv("MC_ACTIVATION_FAULTS") != "1" {
		return nil
	}
	const path = "/data/activation-fault"
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 32 {
		return errors.New("invalid activation fault marker")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	wanted := strings.TrimSpace(string(raw))
	if wanted != "after-verify" && wanted != "before-release" {
		return errors.New("invalid activation fault boundary")
	}
	if wanted != boundary {
		return nil
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	dir, err := os.Open("/data")
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if err = errors.Join(syncErr, closeErr); err != nil {
		return err
	}
	fmt.Printf("activation fault boundary=%s exit=86\n", boundary)
	os.Exit(86)
	return nil
}
