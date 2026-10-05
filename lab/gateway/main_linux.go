//go:build linux

// Lab-only lifecycle/ingress bootstrap; deliberately no RouterOS credentials.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"mikrocentauri.local/core/internal/dnsgate"
	"mikrocentauri.local/core/internal/fakeip"
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
var child *exec.Cmd
var ready bool
var lastError string
var monitor *health.Monitor
var publisher *fakeip.Publisher
var _, fakeRange, _ = net.ParseCIDR("198.18.0.0/15")

func ip(args ...string) error { return exec.Command("/sbin/ip", args...).Run() }
func start() error {
	mu.Lock()
	defer mu.Unlock()
	if child != nil {
		return fmt.Errorf("already running")
	}
	if e := exec.Command("/bin/sing-box", "check", "-c", "/data/singbox.json").Run(); e != nil {
		return fmt.Errorf("config rejected")
	}
	cmd := exec.Command("/bin/sing-box", "run", "-c", "/data/singbox.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	child = cmd
	ready = false
	lastError = ""
	go func() {
		e := cmd.Wait()
		mu.Lock()
		if child == cmd {
			child = nil
			ready = false
			monitor.SetLocalReady(false)
			lastError = fmt.Sprint(e)
		}
		mu.Unlock()
	}()
	iface := os.Getenv("MC_INTERFACE")
	if iface == "" {
		iface = "mc-probe"
	}
	for n := 0; n < 100; n++ {
		if netif, e := net.InterfaceByName("mc-tun"); e == nil && netif.Flags&net.FlagUp != 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0600); e != nil {
		return e
	}
	// Only forwarded ingress enters TUN; locally originated VLESS/DNS sockets stay in main.
	ip("rule", "del", "priority", "10000", "iif", iface, "lookup", "100")
	if e := ip("route", "replace", "default", "dev", "mc-tun", "table", "100"); e != nil {
		return fmt.Errorf("TUN ingress route: %w", e)
	}
	if e := ip("rule", "add", "priority", "10000", "iif", iface, "lookup", "100"); e != nil {
		return fmt.Errorf("TUN ingress rule: %w", e)
	}
	ready = true
	return nil
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

func (g gatewayChecker) Check(ctx context.Context) error {
	if publisher != nil {
		if err := publisher.Reconcile(ctx); err != nil {
			return fmt.Errorf("mapping reconciliation unavailable")
		}
		// An engine cache reset must never qualify UP with stale client aliases.
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:5353")
		}}
		for _, m := range publisher.Mappings() {
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			ips, err := resolver.LookupIP(probeCtx, "ip4", m.Domain)
			cancel()
			if err != nil || len(ips) != 1 || ips[0].String() != m.Fake.String() {
				return fmt.Errorf("engine alias generation mismatch")
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
	if os.Getenv("MC_DYNAMIC_DNS") == "1" {
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
	http.HandleFunc("/control/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		mu.Lock()
		ready = false
		if child != nil {
			child.Process.Kill()
		}
		mu.Unlock()
		monitor.SetLocalReady(false)
		w.WriteHeader(202)
	})
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
		mu.Lock()
		ready = false
		if child != nil {
			child.Process.Signal(syscall.SIGTERM)
		}
		mu.Unlock()
		time.Sleep(time.Second)
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
	gate, err := dnsgate.New(dnsgate.Config{InternalAddress: "127.0.0.1:5354", Selected: strings.Split(os.Getenv("MC_SELECTED_DOMAINS"), ","), Observe: observeDNS}, publisher)
	if err != nil {
		return err
	}
	go func() {
		if err := gate.Serve(context.Background(), ":5353"); err != nil {
			panic(err)
		}
	}()
	return nil
}
