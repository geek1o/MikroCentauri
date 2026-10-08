package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/singbox"
)

func main() {
	if err := run(); err != nil {
		// RouterOS may show only stdout in container logs. App startup errors are
		// already sanitized; make the reason visible without printing inputs.
		if len(os.Args) > 1 && os.Args[1] == "app-run" {
			fmt.Fprintln(os.Stdout, "MikroCentauri startup failed:", err)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: mikrocentauri app-run|app-health|app-provision|app-install-plan|app-install-verify|api-auth-init|api-serve|api-openapi|generate|plan|core-generate|core-check|core-preview|ruleset-import|ruleset-refresh|ruleset-load|endpoint-preview|subscription-refresh|subscription-run|subscription-status|router-inspect|router-plan|router-stage|router-reconcile|router-recover|router-managed-plan|router-watchdog-plan|router-apply|router-managed-reconcile|router-managed-recover|router-rollback|router-verify|router-cleanup (see command -h)")
	}
	action := os.Args[1]
	if action == "app-provision" {
		return appProvisionCommand(os.Args[2:])
	}
	if strings.HasPrefix(action, "app-install-") {
		return appInstallCommand(action, os.Args[2:])
	}
	if strings.HasPrefix(action, "app-") {
		return appCommand(action, os.Args[2:])
	}
	if strings.HasPrefix(action, "api-") {
		return apiCommand(action, os.Args[2:])
	}
	if strings.HasPrefix(action, "ruleset-") {
		return rulesetCommand(action, os.Args[2:])
	}
	if strings.HasPrefix(action, "core-") || strings.HasPrefix(action, "subscription-") || action == "endpoint-preview" {
		return coreCommand(action, os.Args[2:])
	}
	if strings.HasPrefix(action, "router-") {
		return routerCommand(action, os.Args[2:])
	}
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	input := fs.String("config", "", "local application config (contains secrets)")
	output := fs.String("out", "", "private candidate output path")
	sb := fs.String("sing-box", "sing-box", "pinned validator executable")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if action != "generate" && action != "plan" {
		return fmt.Errorf("unsupported command")
	}
	if *input == "" {
		return fmt.Errorf("config path required")
	}
	b, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	c, err := config.Decode(b)
	if err != nil {
		return err
	}
	if action == "plan" {
		desired, err := routeros.Desired(c)
		if err != nil {
			return err
		}
		plan, err := routeros.Plan(c.Instance, nil, desired)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(plan)
	}
	if *output == "" {
		return fmt.Errorf("out path required; generated config contains secrets")
	}
	b, err = singbox.Generate(c)
	if err != nil {
		return err
	}
	// Validate an isolated candidate before replacing any existing output.
	tmp, err := os.CreateTemp("", "mikrocentauri-check-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = singbox.Check(ctx, *sb, tmp.Name()); err != nil {
		return err
	}
	if err = config.WriteAtomic(*output, b); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "validated candidate saved; RouterOS unchanged")
	return nil
}
