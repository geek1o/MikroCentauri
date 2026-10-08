// Disposable HTTPS fixture for browser contracts. Runtime and subscription
// transport are simulated by default; -real-subscriptions enables the production
// downloader. The API, auth, drafts and pinned sing-box validator are real. This executable is never a router/release acceptance test.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/trafficlists"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	data, err := coreconfig.GenerateWithOptions(m, coreconfig.Options{DNSPort: 5353, MixedPort: 2080, CachePath: filepath.Join(r.directory, "validator-cache.db")})
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
	raw, err := json.Marshal(struct {
		Model    coreconfig.Model `json:"model"`
		Revision uint64           `json:"revision"`
	}{m, r.revision + 1})
	if err != nil {
		return err
	}
	if err = config.WriteAtomic(filepath.Join(r.directory, "runtime-model.json"), raw); err != nil {
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
	forwarding := true
	return routeros.Network{IPv6: routeros.IPv6Observation{State: "configured_enabled", Forwarding: &forwarding, EnabledAddresses: 2, DefaultRoutes: 1}, Available: map[string]bool{"system/resource": true, "ip/address": true, "ip/dhcp-server/lease": true, "ip/dns": true, "ip/route": true, "ip/firewall/filter": true, "ipv6/settings": true, "ipv6/address": true, "ipv6/route": true}, Addresses: []routeros.NetworkAddress{{Address: "192.168.88.1/24", Interface: "bridge-lan"}, {Address: "172.30.0.1/30", Interface: "mc-veth"}}, DefaultRoutes: []routeros.NetworkRoute{{Gateway: "10.77.0.1", Table: "main"}}, Devices: []routeros.NetworkDevice{{Hostname: "Lab laptop", Address: "192.168.88.20", MAC: "02:00:00:00:00:20", Status: "bound"}}, DNSServers: []string{"1.1.1.1"}, DNSRemoteRequests: true, FastTrackRules: 1, FastTrackEnabled: 1, MemoryTotal: 1 << 30, MemoryFree: 512 << 20, DiskTotal: 4 << 30, DiskFree: 2 << 30}, nil
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
	realSubscriptions := flag.Bool("real-subscriptions", false, "use the production HTTPS subscription downloader")
	stateDirectory := flag.String("state", "", "persistent private manual-preview state directory")
	listen := flag.String("listen", "127.0.0.1:0", "loopback-only HTTPS listener")
	flag.Parse()
	host, _, listenErr := net.SplitHostPort(*listen)
	addr, addrErr := netip.ParseAddr(host)
	if listenErr != nil || addrErr != nil || !addr.IsLoopback() {
		panic("fixture listener must use a loopback IP")
	}
	if *binary == "" {
		panic("sing-box required")
	}
	dir := *stateDirectory
	var err error
	if dir == "" {
		dir, err = os.MkdirTemp("", "mikrocentauri-webui-")
	} else {
		dir, err = filepath.Abs(dir)
		if err == nil {
			err = os.MkdirAll(dir, 0700)
		}
	}
	if err != nil {
		panic(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		panic(err)
	}
	if *stateDirectory == "" {
		defer os.RemoveAll(dir)
	}
	if _, err = os.Stat(filepath.Join(dir, "auth.json")); os.IsNotExist(err) {
		if err = api.InitializeAuth(dir, []byte("BrowserFixturePassword-2026")); err != nil {
			panic(err)
		}
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
	if *realSubscriptions {
		m = coreconfig.Model{SchemaVersion: 2, Instance: "manual-preview", Mode: "hybrid", Endpoints: []endpoints.Endpoint{}, Groups: []coreconfig.Group{}, Rules: []coreconfig.Rule{}, DefaultOutbound: "direct", DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/manual-preview/cache.db"}}
	}
	rt := &runtime{model: m, revision: 7, binary: *binary, directory: dir}
	if data, e := os.ReadFile(filepath.Join(dir, "runtime-model.json")); e == nil {
		var saved struct {
			Model    coreconfig.Model `json:"model"`
			Revision uint64           `json:"revision"`
		}
		if json.Unmarshal(data, &saved) != nil || saved.Model.Validate() != nil || saved.Revision < 7 {
			panic("invalid saved preview model")
		}
		rt.model, rt.revision = saved.Model, saved.Revision
	}
	providerNode, _ := endpoints.ParseURI("ss://YWVzLTEyOC1nY206c3ViLWZpeHR1cmU@192.0.2.21:8443#Subscription%20node")
	providerNode.Enabled = true
	var provider api.SubscriptionManager = &providers{node: providerNode, states: map[string]subscriptions.State{}}
	if *realSubscriptions {
		provider, err = subscriptions.New(filepath.Join(dir, "provider-cache"), subscriptions.Policy{})
		if err != nil {
			panic(err)
		}
	}
	subs, err := api.NewSubscriptionResources(filepath.Join(dir, "subscriptions"), provider)
	if err != nil {
		panic(err)
	}
	defer subs.Close()
	server := httptest.NewUnstartedServer(nil)
	server.Listener.Close()
	server.Listener, err = net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	origin := "https://" + server.Listener.Addr().String()
	var listManager *trafficlists.Manager
	listURL := ""
	if !*realSubscriptions {
		source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "# test fixture\nservice.example.test\nvideo.example.test\n")
		}))
		defer source.Close()
		roots, _ := x509.SystemCertPool()
		if roots == nil {
			roots = x509.NewCertPool()
		}
		roots.AddCert(source.Certificate())
		listManager, err = trafficlists.New(filepath.Join(dir, "traffic-lists"), subscriptions.Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
		if err != nil {
			panic(err)
		}
		listURL = source.URL
	}
	app, err := api.New(api.Options{TrafficLists: listManager, SimulatedRuntime: true, SimulatedSubscriptions: !*realSubscriptions, Directory: dir, Auth: auth, Model: rt.model, Runtime: rt, Router: &api.RouterResources{Client: routerFixture{}, Instance: m.Instance}, Subscriptions: subs, Origin: origin})
	if err != nil {
		panic(err)
	}
	server.Config.Handler = app
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	data, _ := json.Marshal(map[string]string{"url": origin, "list_url": listURL, "fixture": "simulated-runtime-real-api-real-singbox-validator"})
	fmt.Println(string(data))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
