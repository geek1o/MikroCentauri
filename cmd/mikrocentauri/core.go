package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/subscriptions"
)

// Core commands exchange credentials only through private files. Generation
// remains offline: activation requires the namespace and RouterOS controllers.
func coreCommand(action string, args []string) error {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	input := fs.String("config", "", "private 0600 core model v2 or subscription specification")
	output := fs.String("out", "", "private validated candidate output")
	binary := fs.String("sing-box", "sing-box", "pinned sing-box validator")
	state := fs.String("state", "", "private subscription state directory")
	id := fs.String("id", "", "subscription identifier for status")
	uriFile := fs.String("uri-file", "", "private 0600 endpoint URI file")
	interval := fs.Duration("interval", time.Hour, "periodic subscription refresh interval")
	rulesetState := fs.String("ruleset-state", "", "private verified rule-set store for generation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	switch action {
	case "endpoint-preview":
		if *uriFile == "" {
			return errors.New("uri-file required")
		}
		b, err := readRouterFile(*uriFile, 16<<10, true)
		if err != nil {
			return err
		}
		ep, err := endpoints.ParseURI(strings.TrimSpace(string(b)))
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(ep.Preview())
	case "core-generate", "core-check", "core-preview":
		if *input == "" || (action == "core-generate" && *output == "") {
			return errors.New("private config and candidate output required")
		}
		b, err := readRouterFile(*input, 4<<20, true)
		if err != nil {
			return err
		}
		m, err := coreconfig.Decode(b)
		if err != nil {
			return err
		}
		if action == "core-preview" {
			return json.NewEncoder(os.Stdout).Encode(m.Preview())
		}
		opts := coreconfig.Options{DNSPort: 5353, MixedPort: 2080}
		if len(m.RuleSets) > 0 {
			if *rulesetState == "" {
				return errors.New("private rule-set store required")
			}
			manager, e := rulesets.New(*rulesetState, *binary, rulesets.Policy{})
			if e != nil {
				return e
			}
			for _, ref := range m.RuleSets {
				artifact, e := manager.Load(ref.ID)
				if e != nil {
					return e
				}
				opts.RuleSets = append(opts.RuleSets, artifact)
			}
		}
		b, err = coreconfig.GenerateWithOptions(m, opts)
		if err != nil {
			return err
		}
		f, err := os.CreateTemp("", "mikrocentauri-core-check-*.json")
		if err != nil {
			return errors.New("candidate file unavailable")
		}
		defer os.Remove(f.Name())
		_, err = f.Write(b)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.New("candidate write failed")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err = singbox.Check(ctx, *binary, f.Name()); err != nil {
			return err
		}
		if action == "core-generate" {
			if err = config.WriteAtomic(*output, b); err != nil {
				return err
			}
		}
		fmt.Fprintln(os.Stderr, "core candidate validated")
		return nil
	case "subscription-refresh", "subscription-run", "subscription-status":
		if action == "subscription-run" && *interval < time.Second {
			return errors.New("refresh interval must be at least one second")
		}
		if *state == "" {
			return errors.New("private state directory required")
		}
		manager, err := subscriptions.New(*state, subscriptions.Policy{})
		if err != nil {
			return err
		}
		if action == "subscription-status" {
			s, err := manager.Load(*id)
			if err != nil {
				return err
			}
			return printSubscriptionStatus(s)
		}
		if *input == "" {
			return errors.New("private subscription specification required")
		}
		var spec subscriptions.Spec
		if err = privateJSON(*input, &spec, 64<<10); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		s, refreshErr := manager.Refresh(ctx, spec)
		if refreshErr != nil && s.ID == "" {
			return refreshErr
		}
		if err = printSubscriptionStatus(s); err != nil {
			return err
		}
		if action == "subscription-refresh" {
			return refreshErr
		}
		if err = manager.Run(ctx, []subscriptions.Spec{spec}, *interval); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	default:
		return errors.New("unsupported core command")
	}
}

func printSubscriptionStatus(s subscriptions.State) error {
	previews := make([]endpoints.Preview, 0, len(s.Nodes))
	for _, node := range s.Nodes {
		previews = append(previews, node.Preview())
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		ID          string              `json:"id"`
		LastAttempt time.Time           `json:"last_attempt"`
		LastSuccess time.Time           `json:"last_success"`
		Failure     string              `json:"failure,omitempty"`
		Count       int                 `json:"count"`
		Nodes       []endpoints.Preview `json:"nodes"`
	}{s.ID, s.LastAttempt, s.LastSuccess, s.Failure, len(previews), previews})
}
