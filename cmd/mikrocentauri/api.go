package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/application"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/subscriptions"
)

func apiCommand(action string, args []string) error {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	state := fs.String("state", "", "private API directory")
	password := fs.String("password-file", "", "0600 file, initial password only")
	input := fs.String("config", "", "private v2 model")
	listen := fs.String("listen", "127.0.0.1:8443", "literal HTTPS listen address")
	cert := fs.String("tls-cert", "", "server certificate")
	key := fs.String("tls-key", "", "private server key")
	binary := fs.String("sing-box", "sing-box", "pinned validator")
	out := fs.String("out", "", "OpenAPI output file")
	clients := fs.String("allow-clients", "", "explicit comma separated client CIDRs")
	routerConfig := fs.String("router-config", "", "private HTTPS RouterOS connection file for read-only resources")
	runtimeProfile := fs.String("runtime-profile", "", "private preprovisioned native runtime profile (Linux only)")
	refreshInterval := fs.Duration("subscription-refresh", 0, "periodic refresh interval, 0 disables scheduling")
	ruleState := fs.String("ruleset-state", "", "private verified rule-set store")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected API arguments")
	}
	if action == "api-openapi" {
		if *out == "" {
			return errors.New("output required")
		}
		b, e := json.MarshalIndent(api.OpenAPI(), "", "  ")
		if e != nil {
			return e
		}
		return config.WriteAtomic(*out, append(b, '\n'))
	}
	if *state == "" {
		return errors.New("private API state required")
	}
	if action == "api-auth-init" {
		b, e := readRouterFile(*password, 1024, true)
		if e != nil {
			return errors.New("private password file required")
		}
		return api.InitializeAuth(*state, []byte(strings.TrimSuffix(string(b), "\n")))
	}
	if action != "api-serve" {
		return errors.New("unsupported API command")
	}
	if *password != "" {
		return errors.New("initialize credentials with api-auth-init")
	}
	host, port, e := net.SplitHostPort(*listen)
	portNumber, portError := strconv.Atoi(port)
	addr, err := netip.ParseAddr(host)
	if e != nil || err != nil || portError != nil || portNumber < 1 || portNumber > 65535 || addr.IsUnspecified() || (!addr.IsLoopback() && !addr.IsPrivate()) {
		return errors.New("API listener must be a literal loopback or private LAN address")
	}
	if !addr.IsLoopback() && *clients == "" {
		return errors.New("LAN API requires explicit client CIDRs")
	}
	if *cert == "" || *key == "" {
		return errors.New("HTTPS certificate and private key required")
	}
	if _, e = readRouterFile(*key, 1<<20, true); e != nil {
		return errors.New("private TLS key required")
	}
	raw, e := readRouterFile(*input, 4<<20, true)
	if e != nil {
		return e
	}
	m, e := coreconfig.Decode(raw)
	if e != nil {
		return e
	}
	a, e := api.OpenAuth(*state)
	if e != nil {
		return e
	}
	defer a.Close()
	allowed := []netip.Prefix{}
	if *clients != "" {
		for _, v := range strings.Split(*clients, ",") {
			p, e := netip.ParsePrefix(v)
			if e != nil {
				return errors.New("invalid client CIDR")
			}
			allowed = append(allowed, p)
		}
	}
	validate := func(ctx context.Context, m coreconfig.Model) error {
		options := coreconfig.Options{DNSPort: 5353, MixedPort: 2080}
		if len(m.RuleSets) > 0 {
			if *ruleState == "" {
				return errors.New("rule-set store required")
			}
			manager, e := rulesets.New(*ruleState, *binary, rulesets.Policy{})
			if e != nil {
				return e
			}
			for _, ref := range m.RuleSets {
				artifact, e := manager.Load(ref.ID)
				if e != nil {
					return e
				}
				options.RuleSets = append(options.RuleSets, artifact)
			}
		}
		data, e := coreconfig.GenerateWithOptions(m, options)
		if e != nil {
			return e
		}
		f, e := os.CreateTemp(*state, ".api-check-")
		if e != nil {
			return e
		}
		path := f.Name()
		defer os.Remove(path)
		if _, e = f.Write(data); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		return singbox.Check(ctx, *binary, path)
	}
	directory, e := filepath.Abs(*state)
	if e != nil {
		return e
	}
	manager, e := subscriptions.New(filepath.Join(directory, "subscription-state"), subscriptions.Policy{})
	if e != nil {
		return e
	}
	providers, e := api.NewSubscriptionResources(filepath.Join(directory, "subscription-registry"), manager)
	if e != nil {
		return e
	}
	defer providers.Close()
	if *refreshInterval != 0 && (*refreshInterval < time.Minute || *refreshInterval > 24*time.Hour) {
		return errors.New("invalid subscription refresh interval")
	}
	var routerClient *routeros.Client
	var routerResources *api.RouterResources
	if *routerConfig != "" {
		client, _, err := connectRouter(*routerConfig)
		if err != nil {
			return err
		}
		routerClient = client
		routerResources = &api.RouterResources{Client: client, Instance: m.Instance}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var owner *application.Runtime
	var runtimeAdapter api.Runtime
	if *runtimeProfile != "" {
		if routerClient == nil {
			return errors.New("native runtime requires HTTPS router connection")
		}
		var profile application.Profile
		if privateJSON(*runtimeProfile, &profile, 1<<20) != nil {
			return errors.New("invalid runtime profile")
		}
		setup, done := context.WithTimeout(ctx, 30*time.Second)
		owner, e = application.New(setup, profile, m, routerClient, *binary)
		done()
		if e != nil {
			return errors.Join(errors.New("native runtime startup preflight failed"), e)
		}
		runtimeAdapter = owner
		defer func() {
			c, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			owner.Close(c)
		}()
	}
	handler, e := api.New(api.Options{Runtime: runtimeAdapter, Subscriptions: providers, Router: routerResources, Directory: directory, Auth: a, Model: m, Validate: validate, Origin: "https://" + *listen, Clients: allowed})
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	pair, e := tls.LoadX509KeyPair(*cert, *key)
	if e != nil {
		return errors.New("invalid server certificate/key")
	}
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return errors.New("HTTPS API bind failed")
	}
	defer listener.Close()
	srv.TLSConfig.Certificates = []tls.Certificate{pair}
	done := make(chan error, 3)
	go func() { done <- srv.Serve(tls.NewListener(listener, srv.TLSConfig)) }()
	if owner != nil {
		go func() {
			e := owner.RunListeners(ctx)
			if e == nil && ctx.Err() == nil {
				e = errors.New("runtime stopped")
			}
			done <- e
		}()
	}
	if *refreshInterval != 0 {
		go func() {
			e := providers.Run(ctx, *refreshInterval)
			if e != nil {
				done <- e
			}
		}()
	}
	defer srv.Close()
	select {
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		stop()
		return errors.New("application listener or runtime failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
