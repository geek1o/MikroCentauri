//go:build linux

// Lab-only lifecycle/ingress bootstrap; deliberately no RouterOS credentials.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var mu sync.Mutex
var child *exec.Cmd
var ready bool
var lastError string
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
	if len(ips) == 0 || !fakeRange.Contains(ips[0]) {
		return fmt.Errorf("DNS probe: selected fixture not FakeIP")
	}
	return nil
}
func state(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	ok, reason := ready && child != nil, lastError
	mu.Unlock()
	if ok {
		if iface, err := net.InterfaceByName("mc-tun"); err != nil || iface.Flags&net.FlagUp == 0 {
			ok, reason = false, "TUN unavailable"
		} else if err := dnsReady(); err != nil {
			ok, reason = false, err.Error()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		w.WriteHeader(503)
	}
	json.NewEncoder(w).Encode(map[string]any{"ready": ok, "error": reason})
}
func main() {
	if e := start(); e != nil {
		mu.Lock()
		lastError = e.Error()
		ready = false
		mu.Unlock()
		fmt.Println("gateway setup:", e)
	}
	http.HandleFunc("/", state)
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
		state(w, r)
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
