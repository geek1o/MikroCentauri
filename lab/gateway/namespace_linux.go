//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/activation"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/engineguard"
	"mikrocentauri.local/core/internal/generation"
	"mikrocentauri.local/core/internal/namespace"
)

var namespaceStore *namespace.Store
var policyActivation *activation.Controller
var activeNames []string
var dnsSwitch = dnsgate.NewSwitcher(nil)

func retiredNames(known, active []string) []string {
	present := map[string]bool{}
	for _, n := range active {
		present[n] = true
	}
	var out []string
	for _, n := range known {
		if !present[n] {
			out = append(out, n)
		}
	}
	return out
}
func installPolicy(known, active []string) error {
	allocator, err := dnsgate.NewAllocator("127.0.0.1:5354")
	if err != nil {
		return err
	}
	candidate, err := generation.New(generation.Config{Selected: known, Active: active, Prefix: netip.MustParsePrefix("198.18.0.0/15"), Capacity: 32}, allocator, publisher)
	if err != nil {
		return err
	}
	gate, err := dnsgate.New(dnsgate.Config{InternalAddress: "127.0.0.1:5354", Selected: active, Retired: retiredNames(known, active), RealAddress: "10.77.0.20:53", Observe: observeDNS}, candidate)
	if err != nil {
		return err
	}
	mu.Lock()
	admission = candidate
	selectedNames = append([]string{}, known...)
	activeNames = append([]string{}, active...)
	mu.Unlock()
	return dnsSwitch.Install(gate)
}
func setupNamespaceDNS() error {
	if os.Getenv("MC_NAMESPACE_POLICY") == "1" {
		var err error
		namespaceStore, err = namespace.New(namespace.Config{Directory: "/data/namespace", Initial: selectedNames, Capacity: 32})
		if err != nil {
			return err
		}
		s, err := namespaceStore.Snapshot()
		if err != nil {
			return err
		}
		if s.Pending != nil {
			dnsSwitch.Hold()
		}
		if err = installPolicy(s.Known, s.Active); err != nil {
			return err
		}
		policyActivation, err = activation.New(namespaceStore, gatewayActivation{})
		if err != nil {
			return err
		}
	} else {
		if err := installPolicy(selectedNames, selectedNames); err != nil {
			return err
		}
	}
	go func() {
		if err := dnsgate.Serve(context.Background(), ":5353", dnsSwitch); err != nil {
			panic(err)
		}
	}()
	return nil
}

// Caller holds lifecycleMu. Waiting on childDone never holds mu, because the
// sole child reaper needs mu to clear its identity after closing that channel.
func stopLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return stopLockedContext(ctx)
}
func stopLockedContext(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	mu.Lock()
	ready = false
	dnsSwitch.Hold()
	if admission != nil {
		admission.Revoke()
	}
	err := quarantineContext(ctx)
	cmd, done := child, childDone
	mu.Unlock()
	monitor.SetLocalReady(false)
	if cmd != nil {
		if signalErr := cmd.Process.Signal(syscall.SIGTERM); signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
			return errors.Join(err, signalErr)
		}
		select {
		case <-done:
		case <-ctx.Done():
			return errors.Join(err, fmt.Errorf("engine graceful close incomplete: %w", ctx.Err()))
		}
		mu.Lock()
		if child == cmd {
			child = nil
		}
		mu.Unlock()
	}
	return err
}

var errNativeLeaseTransport = errors.New("native lease transport unavailable")

// Fixed lab-only resources: this helper cannot accept a caller-supplied URL.
func nativeLeaseRequest(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://172.30.0.1/rest/"+path, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("mc-lab", "DisposableLabOnly-2026")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, errNativeLeaseTransport
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New("native lease request rejected")
	}
	return raw, nil
}
func revokeNativeLease(ctx context.Context) error {
	if os.Getenv("MC_NATIVE_LEASE") != "1" {
		return errors.New("namespace change requires native lease fixture")
	}
	// Wait for the observer to consume the now503 readiness before removing its
	// token. Otherwise its stale UP state could renew once during the transition.
	for {
		raw, err := nativeLeaseRequest(ctx, "GET", "tool/netwatch", nil)
		if errors.Is(err, errNativeLeaseTransport) && ctx.Err() == nil {
			// Container startup may precede native network availability. Retry
			// only this read under the caller's deadline; never repeat writes
			// or accept unavailable native state as a revoked lease.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
		if err != nil {
			return err
		}
		var rows []map[string]any
		if err = json.Unmarshal(raw, &rows); err != nil {
			return err
		}
		var found []map[string]any
		for _, r := range rows {
			if r["comment"] == "mikrocentauri:lab:netwatch:readiness" {
				found = append(found, r)
			}
		}
		if len(found) != 1 || found[0]["host"] != "172.30.0.2" || found[0]["port"] != "9099" {
			return errors.New("native observer mismatch")
		}
		if found[0]["disabled"] == "true" || found[0]["status"] == "down" {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, err := nativeLeaseRequest(ctx, "POST", "system/script/run", strings.NewReader(`{"number":"mc-lab-down"}`)); err != nil {
		return err
	}
	raw, err := nativeLeaseRequest(ctx, "GET", "ip/firewall/address-list", nil)
	if err != nil {
		return err
	}
	var rows []map[string]any
	if err = json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	for _, r := range rows {
		if r["list"] == "mc-lab-up-lease" {
			return errors.New("native readiness not revoked")
		}
	}
	return nil
}
func rewritePolicy(known, active []string) error {
	data, err := os.ReadFile("/data/singbox.json")
	if err != nil {
		return err
	}
	if namespaceStore != nil {
		snapshot, e := namespaceStore.Snapshot()
		if e != nil {
			return e
		}
		previous := engineguard.Validate(data, engineguard.Config{Selected: snapshot.Known, Active: snapshot.Active})
		proposed := engineguard.Validate(data, engineguard.Config{Selected: known, Active: active})
		if previous != nil && proposed != nil {
			return errors.New("namespace config is neither committed nor pending generation")
		}
	}
	var c map[string]any
	if err = json.Unmarshal(data, &c); err != nil {
		return err
	}
	dns := c["dns"].(map[string]any)
	for _, v := range dns["rules"].([]any) {
		r := v.(map[string]any)
		if _, ok := r["domain"]; ok {
			r["domain"] = known
		}
	}
	route := c["route"].(map[string]any)
	rules := []any{map[string]any{"action": "hijack-dns", "inbound": []string{"dns-in"}}, map[string]any{"action": "route", "source_ip_cidr": []string{"192.168.88.30/32"}, "outbound": "direct"}, map[string]any{"action": "route", "source_ip_cidr": []string{"192.168.88.20/32"}, "outbound": "proxy"}}
	if len(active) > 0 {
		rules = append(rules, map[string]any{"action": "route", "domain": active, "outbound": "proxy"})
	}
	if retired := retiredNames(known, active); len(retired) > 0 {
		rules = append(rules, map[string]any{"action": "route", "domain": retired, "outbound": "direct"})
	}
	rules = append(rules, map[string]any{"action": "sniff"})
	if len(active) > 0 {
		rules = append(rules, map[string]any{"action": "route", "domain": active, "outbound": "proxy"})
	}
	route["rules"] = rules
	data, err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err = engineguard.Validate(data, engineguard.Config{Selected: known, Active: active}); err != nil {
		return err
	}
	f, err := os.CreateTemp("/data", ".namespace-config-")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(path, "/data/singbox.json"); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func namespaceDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(405)
		return
	}
	if namespaceStore == nil {
		http.Error(w, "namespace controls disabled", 404)
		return
	}
	s, err := namespaceStore.Snapshot()
	if err != nil {
		http.Error(w, "namespace unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}
func namespaceControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if namespaceStore == nil {
		http.Error(w, "namespace controls disabled", 404)
		return
	}
	var q struct {
		Revision uint64   `json:"revision"`
		Active   []string `json:"active"`
		Resume   bool     `json:"resume"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 8193))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		http.Error(w, "invalid namespace request", 400)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "trailing namespace request", 400)
		return
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	s, err := namespaceStore.Snapshot()
	if err != nil {
		http.Error(w, "namespace unavailable", 409)
		return
	}
	if q.Resume {
		if s.Pending == nil || q.Revision != s.Pending.Revision || q.Active != nil {
			http.Error(w, "no matching pending revision", 409)
			return
		}
	} else {
		if s.Pending != nil || q.Revision != s.Revision {
			http.Error(w, "stale or pending namespace revision", 409)
			return
		}
		canary := false
		for _, n := range q.Active {
			if n == "selected.test" {
				canary = true
			}
		}
		if !canary {
			http.Error(w, "lab canary must remain active", 409)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	var committed namespace.Snapshot
	if q.Resume {
		committed, err = policyActivation.Recover(ctx)
	} else {
		committed, err = policyActivation.Apply(ctx, q.Revision, q.Active)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("namespace activation denied: %v", err), 409)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(committed)
}
