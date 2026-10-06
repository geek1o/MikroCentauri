// Disposable HTTPS fixture for browser contracts. Runtime and subscription
// transport are simulated; the production API, auth, drafts and pinned sing-box
// validator are real. This executable is never a router/release acceptance test.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/subscriptions"
)

type runtime struct {
	model             coreconfig.Model
	revision          uint64
	binary, directory string
}

func (r *runtime) View() api.RuntimeView            { return api.RuntimeView{Revision: r.revision, Ready: true} }
func (r *runtime) Model() (coreconfig.Model, error) { return r.model.Clone() }
func (r *runtime) SingBoxVersion(ctx context.Context) (string, error) {
	data, err := exec.CommandContext(ctx, r.binary, "version").Output()
	if err != nil {
		return "", err
	}
	first, _, _ := strings.Cut(string(data), "\n")
	if first != "sing-box version "+singbox.Version {
		return "", errors.New("unexpected version")
	}
	return singbox.Version, nil
}
func (r *runtime) Validate(ctx context.Context, revision uint64, m coreconfig.Model) error {
	if revision != r.revision {
		return errors.New("stale")
	}
	data, err := coreconfig.GenerateWithOptions(m, coreconfig.Options{DNSPort: 5353, MixedPort: 2080,CachePath:filepath.Join(r.directory,"validator-cache.db")})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.directory, "validator-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return singbox.Check(ctx, r.binary, f.Name())
}
func (r *runtime) Apply(ctx context.Context, revision uint64, m coreconfig.Model) error {
	if err := r.Validate(ctx, revision, m); err != nil {
		return err
	}
	r.model = m
	r.revision++
	return nil
}

type providers struct {
	node   endpoints.Endpoint
	states map[string]subscriptions.State
}

type routerFixture struct{}

func (routerFixture) Capabilities(context.Context) (routeros.Capabilities, error) {
	return routeros.Capabilities{Version: "7.24.5", Architecture: "x86_64", Board: "CHR", Platform: "MikroTik", VersionSupported: true, VersionSupportReason: "simulated browser fixture", Packages: []routeros.Package{{Name: "routeros", Version: "7.24.5"}, {Name: "container", Version: "7.24.5"}}, Interfaces: []routeros.Interface{{Name: "bridge-lan", Type: "bridge", Running: true}, {Name: "ether1", Type: "ether", Running: true}, {Name: "mc-veth", Type: "veth", Running: true}}, Resources: map[string]bool{"ip/route": true, "tool/netwatch": true}}, nil
}
func (routerFixture) Discover(context.Context) ([]routeros.Object, error) {
	return []routeros.Object{}, nil
}
func (routerFixture) Network(context.Context) (routeros.Network, error) {
	return routeros.Network{Available: map[string]bool{"system/resource": true, "ip/address": true, "ip/dhcp-server/lease": true, "ip/dns": true, "ip/route": true, "ip/firewall/filter": true}, Addresses: []routeros.NetworkAddress{{Address: "192.168.88.1/24", Interface: "bridge-lan"}, {Address: "172.30.0.1/30", Interface: "mc-veth"}}, DefaultRoutes: []routeros.NetworkRoute{{Gateway: "10.77.0.1", Table: "main"}}, Devices: []routeros.NetworkDevice{{Hostname: "Lab laptop", Address: "192.168.88.20", MAC: "02:00:00:00:00:20", Status: "bound"}}, DNSServers: []string{"1.1.1.1"}, DNSRemoteRequests: true, FastTrackRules: 1, FastTrackEnabled: 1, MemoryTotal: 1 << 30, MemoryFree: 512 << 20, DiskTotal: 4 << 30, DiskFree: 2 << 30}, nil
}

func (p *providers) Load(id string) (subscriptions.State, error) {
	if s, ok := p.states[id]; ok {
		return s, nil
	}
	return subscriptions.State{ID: id}, nil
}
func (p *providers) Refresh(_ context.Context, spec subscriptions.Spec) (subscriptions.State, error) {
	now := time.Now().UTC()
	s := subscriptions.State{ID: spec.ID, LastAttempt: now, LastSuccess: now, ImportedCount: 1, Nodes: []endpoints.Endpoint{p.node}}
	p.states[spec.ID] = s
	return s, nil
}
func main() {
	binary := flag.String("sing-box", "", "pinned real validator")
	flag.Parse()
	if *binary == "" {
		panic("sing-box required")
	}
	dir, err := os.MkdirTemp("", "mikrocentauri-webui-")
	if err != nil {
		panic(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	if err = api.InitializeAuth(dir, []byte("BrowserFixturePassword-2026")); err != nil {
		panic(err)
	}
	auth, err := api.OpenAuth(dir)
	if err != nil {
		panic(err)
	}
	defer auth.Close()
	node, err := endpoints.ParseURI("ss://YWVzLTEyOC1nY206Zml4dHVyZS1zZWNyZXQ@192.0.2.20:8443#Lab%20proxy")
	if err != nil {
		panic(err)
	}
	node.Enabled = true
	m := coreconfig.Model{SchemaVersion: 2, Instance: "webui-fixture", Mode: "socksify", Endpoints: []endpoints.Endpoint{node}, Groups: []coreconfig.Group{{ID: "proxy", Type: "selector", Members: []string{node.ID}, Selected: node.ID}}, Rules: []coreconfig.Rule{}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/webui-fixture/cache.db"}}
	rt := &runtime{model: m, revision: 7, binary: *binary, directory: dir}
	providerNode, _ := endpoints.ParseURI("ss://YWVzLTEyOC1nY206c3ViLWZpeHR1cmU@192.0.2.21:8443#Subscription%20node")
	providerNode.Enabled = true
	subs, err := api.NewSubscriptionResources(filepath.Join(dir, "subscriptions"), &providers{node: providerNode, states: map[string]subscriptions.State{}})
	if err != nil {
		panic(err)
	}
	defer subs.Close()
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	app, err := api.New(api.Options{Directory: dir, Auth: auth, Model: m, Runtime: rt, Router: &api.RouterResources{Client: routerFixture{}, Instance: m.Instance}, Subscriptions: subs, Origin: origin})
	if err != nil {
		panic(err)
	}
	server.Config.Handler = app
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	data, _ := json.Marshal(map[string]string{"url": origin, "fixture": "simulated-runtime-real-api-real-singbox-validator"})
	fmt.Println(string(data))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
