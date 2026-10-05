//go:build linux

// Lab-only lifecycle/ingress bootstrap with public disposable fixture credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/generation"
	"mikrocentauri.local/core/internal/health"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/realdns"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var mu sync.Mutex
var lifecycleMu sync.Mutex
var child *exec.Cmd
var childDone chan struct{}
var ready bool
var lastError string
var lastProbeError string
var monitor *health.Monitor
var publisher *fakeip.Publisher
var admission *generation.Admission
var selectedNames []string
var _, fakeRange, _ = net.ParseCIDR("198.18.0.0/15")

func start() error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if policyActivation != nil {
		_, err := policyActivation.Recover(ctx)
		return err
	}
	return startLocked(ctx)
}

func startLocked(ctx context.Context) error {
	// Preserve the legacy non-namespace start contract: rejecting an already
	// running engine must not stop that healthy generation during cleanup.
	mu.Lock()
	alreadyRunning := child != nil
	mu.Unlock()
	if alreadyRunning {
		return fmt.Errorf("already running")
	}
	err := startEngineLocked(ctx)
	if err == nil {
		err = releaseLocked(ctx)
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		defer cancel()
		return errors.Join(err, stopLockedContext(cleanup))
	}
	return nil
}

// Caller holds lifecycleMu. The verified engine stays quarantined until the
// activation controller commits the durable namespace and calls Release.
func startEngineLocked(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if child != nil {
		return fmt.Errorf("already running")
	}
	ready = false
	if admission != nil {
		dnsSwitch.Hold()
	}
	monitor.SetLocalReady(false)
	if e := quarantineContext(ctx); e != nil {
		return e
	}
	if admission != nil {
		admission.Revoke()
		if e := generationPreflight(); e != nil {
			lastError = "generation preflight denied"
			return e
		}
	}
	if e := exec.CommandContext(ctx, "/bin/sing-box", "check", "-c", "/data/singbox.json").Run(); e != nil {
		return fmt.Errorf("config rejected")
	}
	cmd := exec.Command("/bin/sing-box", "run", "-c", "/data/singbox.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	child = cmd
	done := make(chan struct{})
	childDone = done
	ready = false
	lastError = ""
	go func() {
		e := cmd.Wait()
		close(done)
		mu.Lock()
		if child == cmd {
			child = nil
			ready = false
			if admission != nil {
				dnsSwitch.Hold()
			}
			if admission != nil && admission.Snapshot().Admitted {
				admission.Revoke()
			}
			_ = quarantine()
			monitor.SetLocalReady(false)
			lastError = fmt.Sprint(e)
		}
		mu.Unlock()
	}()
	fail := func(e error) error {
		ready = false
		if admission != nil && admission.Snapshot().Admitted {
			admission.Revoke()
		}
		quarantineErr := quarantine()
		// The caller performs SIGTERM + wait after mu is released. A forced
		// kill here would prevent the stock allocator persisting its cursor.
		lastError = "generation admission denied"
		return errors.Join(e, quarantineErr)
	}
	for n := 0; n < 100; n++ {
		if netif, e := net.InterfaceByName("mc-tun"); e == nil && netif.Flags&net.FlagUp != 0 {
			break
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-done:
			return fail(fmt.Errorf("engine exited before admission"))
		case <-time.After(50 * time.Millisecond):
		}
	}
	if e := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); e != nil {
		return fail(e)
	}
	if admission != nil {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		var e error
		for n := 0; n < 5; n++ {
			e = admission.Admit(ctx)
			if e == nil {
				break
			}
			if ctx.Err() != nil {
				break
			}
			select {
			case <-ctx.Done():
				return fail(ctx.Err())
			case <-done:
				return fail(fmt.Errorf("engine exited during admission"))
			case <-time.After(250 * time.Millisecond):
			}
		}
		if e != nil {
			return fail(e)
		}
	}
	return ctx.Err()
}

func releaseLocked(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if child == nil || (admission != nil && !admission.Snapshot().Admitted) {
		return fmt.Errorf("no verified engine to release")
	}
	select {
	case <-childDone:
		return fmt.Errorf("verified engine exited before release")
	default:
	}

	// Only forwarded ingress enters TUN; locally originated VLESS/DNS sockets stay in main.
	if e := exec.CommandContext(ctx, "/sbin/ip", "route", "replace", "default", "dev", "mc-tun", "table", "100").Run(); e != nil {
		return fmt.Errorf("TUN ingress route: %w", e)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if admission != nil {
		if e := dnsSwitch.Release(); e != nil {
			return e
		}
	}
	ready = true
	return ctx.Err()
}

// Probe the DNS dataplane, not merely the management HTTP listener.
func dnsReady() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5353")
	}}
	ips, err := resolver.LookupIP(ctx, "ip4", "selected.test")
	if err != nil {
		return fmt.Errorf("DNS probe: %w", err)
	}
	if len(ips) == 0 || !fakeRange.Contains(ips[0]) || ips[0].String() != "198.18.0.2" {
		return fmt.Errorf("DNS probe: selected fixture not FakeIP")
	}
	return nil
}

// The static cached-IP experiment qualifies its one known mapping before UP.
// This is not a dynamic DNS publication protocol for arbitrary FakeIP addresses.
type gatewayChecker struct{ proxy health.Checker }

func (g gatewayChecker) Check(ctx context.Context) (probeError error) {
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		lastProbeError = ""
		if probeError != nil {
			lastProbeError = probeError.Error()
		}
	}()
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	if admission != nil {
		mu.Lock()
		active := ready && child != nil
		mu.Unlock()
		if !active {
			return fmt.Errorf("engine unavailable")
		}
		if err := admission.Validate(ctx); err != nil {
			mu.Lock()
			ready = false
			_ = quarantine()
			if child != nil {
				_ = child.Process.Kill()
			}
			mu.Unlock()
			monitor.SetLocalReady(false)
			return fmt.Errorf("engine generation denied")
		}
	}
	if publisher != nil {
		if err := publisher.Reconcile(ctx); err != nil {
			return fmt.Errorf("mapping reconciliation unavailable: %w", err)
		}
		// Full active+retired namespace is checked through the private allocator
		// by admission.Validate; retired public DNS deliberately returns real IP.
		if admission == nil {
			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5353")
			}}
			for _, m := range publisher.Mappings() {
				ips, err := resolver.LookupIP(ctx, "ip4", m.Domain)
				if err != nil || len(ips) != 1 || ips[0].String() != m.Fake.String() {
					return fmt.Errorf("engine alias generation mismatch")
				}
			}
		}
	}
	if iface, err := net.InterfaceByName("mc-tun"); err != nil || iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("TUN unavailable")
	}
	if err := dnsReady(); err != nil {
		return err
	}
	iface := os.Getenv("MC_INTERFACE")
	if iface == "" {
		iface = "mc-probe"
	}
	rules, err := exec.CommandContext(ctx, "/sbin/ip", "rule", "list").Output()
	if err != nil || !strings.Contains(string(rules), "iif "+iface+" lookup 100") {
		return fmt.Errorf("ingress policy unavailable")
	}
	route, err := exec.CommandContext(ctx, "/sbin/ip", "route", "show", "table", "100").Output()
	if err != nil || !strings.Contains(string(route), "default dev mc-tun") {
		return fmt.Errorf("ingress route unavailable")
	}
	return g.proxy.Check(ctx)
}
func state(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	local := ready && child != nil
	mu.Unlock()
	if !local {
		monitor.SetLocalReady(false)
	}
	snapshot := monitor.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	if !snapshot.Ready {
		w.WriteHeader(503)
	}
	json.NewEncoder(w).Encode(snapshot)
}
func main() {
	// Stock cache open mode is0666; make all child-created state private.
	syscall.Umask(0077)
	if os.Getenv("MC_DYNAMIC_DNS") == "1" {
		if err := os.Chmod("/data", 0700); err != nil {
			panic(err)
		}
		if err := dynamicDNS(); err != nil {
			panic(err)
		}
	}
	proxy, err := health.NewHTTPProbe(health.HTTPProbeConfig{SOCKSAddress: "127.0.0.1:2080", URL: "http://selected.test:8080/health-canary", ExpectedPeerIP: "10.77.0.10", Timeout: 2 * time.Second})
	if err != nil {
		panic(err)
	}
	monitor, err = health.NewMonitor(gatewayChecker{proxy}, health.Settings{Failures: 2, Successes: 3, Interval: time.Second})
	if err != nil {
		panic(err)
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			local := ready && child != nil
			mu.Unlock()
			monitor.SetLocalReady(local)
			monitor.Sample(context.Background())
		}
	}()

	if e := start(); e != nil {
		mu.Lock()
		lastError = e.Error()
		ready = false
		mu.Unlock()
		fmt.Println("gateway setup:", e)
	}
	http.HandleFunc("/", state)
	http.HandleFunc("/diagnostics/dns", dnsDiagnostics)
	http.HandleFunc("/diagnostics/generation", generationDiagnostics)
	http.HandleFunc("/control/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		lifecycleMu.Lock()
		e := stopLocked()
		lifecycleMu.Unlock()
		if e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		w.WriteHeader(202)
	})
	http.HandleFunc("/diagnostics/namespace", namespaceDiagnostics)
	http.HandleFunc("/control/namespace", namespaceControl)
	http.HandleFunc("/control/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if e := start(); e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]bool{"starting": true})
	})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		lifecycleMu.Lock()
		if e := stopLocked(); e != nil {
			fmt.Println("gateway shutdown:", e)
		}
		lifecycleMu.Unlock()
		os.Exit(0)
	}()
	if e := http.ListenAndServe(":9099", nil); e != nil {
		panic(e)
	}
}

func dynamicDNS() error {
	// Public disposable credentials, only in this explicitly enabled isolated mode.
	c, err := routeros.NewLabClient("http://172.30.0.1/rest", "mc-lab", "DisposableLabOnly-2026", nil)
	if err != nil {
		return err
	}
	b, err := routeros.NewLabMappingBackend(c)
	if os.Getenv("MC_NATIVE_LEASE") == "1" {
		b, err = routeros.NewLabLeaseMappingBackend(c)
	}
	if err != nil {
		return err
	}
	r, err := realdns.New(realdns.Config{Address: "10.77.0.20:53"})
	if err != nil {
		return err
	}
	publisher, err = fakeip.New(fakeip.Config{Directory: "/data/publication", Prefix: netip.MustParsePrefix("198.18.0.0/15"), Capacity: 32}, r, b)
	if err != nil {
		return err
	}
	selectedNames = strings.Split(os.Getenv("MC_SELECTED_DOMAINS"), ",")
	return setupNamespaceDNS()
}
