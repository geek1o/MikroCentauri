package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"time"

	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/subscriptions"
)

func checkSubscription(ctx context.Context, p *grouphealth.Prober, node endpoints.Endpoint, id, path, directory string, out io.Writer) error {
	raw, err := readPrivateInput(path, 2<<20)
	if err != nil {
		return errors.New("private subscription registry unavailable")
	}
	var specs []subscriptions.Spec
	if json.Unmarshal(raw, &specs) != nil || len(specs) > 64 {
		return errors.New("invalid private subscription registry")
	}
	var selected *subscriptions.Spec
	for _, spec := range specs {
		if spec.ID == id {
			if selected != nil {
				return errors.New("ambiguous subscription ID")
			}
			copy := spec
			selected = &copy
		}
	}
	if selected == nil {
		return errors.New("subscription ID not configured")
	}
	u, err := url.Parse(selected.URL)
	if err != nil || len(selected.URL) > 8192 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("subscription diagnostic requires a private HTTPS source")
	}
	selected.ProxyNode = node.ID // Diagnostic override stays in RAM, never in the registry.
	temporary, err := os.MkdirTemp(directory, "subscription-")
	if err != nil {
		return errors.New("private subscription diagnostic directory unavailable")
	}
	defer os.RemoveAll(temporary)
	m, err := subscriptions.New(temporary, subscriptions.Policy{})
	if err != nil {
		return errors.New("isolated subscription manager unavailable")
	}
	var state subscriptions.State
	err = p.WithEndpointProxy(ctx, node, func(ctx context.Context, proxy *url.URL) error {
		dial, err := subscriptions.HTTPProxyDialer(proxy)
		if err != nil {
			return err
		}
		state, err = m.RefreshVia(ctx, *selected, dial)
		return err
	})
	return json.NewEncoder(out).Encode(struct {
		Scope        string    `json:"scope"`
		CheckedAt    time.Time `json:"checked_at"`
		Success      bool      `json:"success"`
		RoutingReady bool      `json:"routing_ready"`
		SourceCount  int       `json:"source_count"`
		NodeCount    int       `json:"node_count"`
		IssueCount   int       `json:"issue_count"`
		FailureCode  string    `json:"failure_code,omitempty"`
	}{"isolated subscription download; no live registry, cache, draft or routing changes", time.Now().UTC(), err == nil, false, state.SourceCount, len(state.Nodes), len(state.Issues), func() string {
		if err == nil {
			return ""
		}
		if code := subscriptions.SafeFailureCode(state.FailureCode); code != "" {
			return code
		}
		return "proxy_unavailable"
	}()})
}
