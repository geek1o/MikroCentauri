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
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/rulesets"
	"mikrocentauri.local/core/internal/singbox"
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
	host, _, e := net.SplitHostPort(*listen)
	addr, err := netip.ParseAddr(host)
	if e != nil || err != nil || addr.IsUnspecified() || (!addr.IsLoopback() && !addr.IsPrivate()) {
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
	handler, e := api.New(api.Options{Directory: directory, Auth: a, Model: m, Validate: validate, Origin: "https://" + *listen, Clients: allowed})
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServeTLS(*cert, *key) }()
	select {
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTPS API listener failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
