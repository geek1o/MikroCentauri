package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/platform/routeros"
)

type routerConnection struct {
	BaseURL  string `json:"base_url"`
	Username string `json:"username"`
	Password string `json:"password"`
	CAFile   string `json:"ca_file,omitempty"`
}
type routerArtifact struct {
	SchemaVersion int                 `json:"schema_version"`
	Target        string              `json:"target"`
	Plan          routeros.ChangePlan `json:"plan"`
	Desired       []routeros.Object   `json:"desired"`
}

func readRouterFile(path string, limit int64, private bool) ([]byte, error) {
	if private {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			st, err := os.Lstat(dir)
			if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("private input directory must not contain symlinks")
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("input unavailable or symlink")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit || (private && st.Mode().Perm() != 0600 && st.Mode().Perm() != 0400) {
		return nil, errors.New("input must be a bounded regular file; private files require owner-only0400 or0600")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("input exceeds limit or is unreadable")
	}
	return data, nil
}

func privateJSON(path string, value any, limit int64) error {
	data, err := readRouterFile(path, limit, true)
	if err != nil {
		return err
	}
	// Reject duplicate keys throughout the artifact as well as unknown fields.
	if err = uniqueJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return errors.New("invalid private input JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing private input JSON")
	}
	return nil
}
func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("private input nesting exceeds limit")
		}
		tok, err := d.Token()
		if err != nil {
			return errors.New("invalid private input JSON")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return errors.New("invalid private input JSON")
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return errors.New("duplicate private input key")
				}
				seen[s] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid private input JSON")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing private input JSON")
	}
	return nil
}
func connectRouter(path string) (*routeros.Client, string, error) {
	var cfg routerConnection
	if err := privateJSON(path, &cfg, 64<<10); err != nil {
		return nil, "", err
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, "", errors.New("router credentials required in private file")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The accepted CHR control plane requires a bounded physical TLS pool.
	// Keep the one socket warm: cold parallel handshakes caused native broken
	// pipes under repeated profile proofs. Logical readers remain context-bound.
	transport.ForceAttemptHTTP2 = false
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		data, err := readRouterFile(cfg.CAFile, 1<<20, false)
		if err != nil {
			return nil, "", errors.New("router CA unavailable")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, "", errors.New("invalid router CA")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client, err := routeros.NewClient(cfg.BaseURL, cfg.Username, cfg.Password, &http.Client{Transport: transport, Timeout: 10 * time.Second})
	return client, strings.TrimSuffix(cfg.BaseURL, "/"), err
}
func routerCommand(action string, args []string) error {
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	target := fs.String("router-config", "", "private0600 connection JSON")
	input := fs.String("config", "", "local application config")
	out := fs.String("out", "", "private plan artifact path")
	planPath := fs.String("plan", "", "reviewed private plan artifact")
	desiredPath := fs.String("desired", "", "private complete managed desired-state JSON")
	watchdogPath := fs.String("watchdog-config", "", "private generated watchdog specification")
	instance := fs.String("instance", "", "exact managed ownership instance")
	journal := fs.String("journal", "", "exclusive private transaction directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *target == "" {
		return errors.New("router-config required; positional arguments unsupported")
	}
	switch action {
	case "router-inspect", "router-plan", "router-stage", "router-reconcile", "router-recover", "router-managed-plan", "router-watchdog-plan", "router-apply", "router-managed-reconcile", "router-managed-recover", "router-rollback", "router-verify", "router-cleanup":
	default:
		return errors.New("unsupported router command")
	}
	client, url, err := connectRouter(*target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	caps, err := client.Capabilities(ctx)
	if err != nil {
		return err
	}
	if action == "router-inspect" {
		return json.NewEncoder(os.Stdout).Encode(caps)
	}
	if !caps.VersionSupported {
		return errors.New("router version/platform has no accepted staging baseline")
	}
	for _, path := range []string{"ip/route", "ip/firewall/nat", "ip/firewall/mangle", "ip/firewall/filter", "tool/netwatch", "system/scheduler"} {
		if !caps.Resources[path] {
			return errors.New("required managed resource unavailable")
		}
	}
	if action == "router-managed-plan" || action == "router-watchdog-plan" {
		if *out == "" {
			return errors.New("out required")
		}
		var desired struct {
			Instance string            `json:"instance"`
			Objects  []routeros.Object `json:"objects"`
		}
		if action == "router-watchdog-plan" {
			if *watchdogPath == "" {
				return errors.New("watchdog-config required")
			}
			var spec routeros.WatchdogSpec
			if err = privateJSON(*watchdogPath, &spec, 1<<20); err != nil {
				return err
			}
			bundle, buildErr := routeros.WatchdogBundle(spec)
			if buildErr != nil {
				return buildErr
			}
			desired.Instance = spec.Instance
			desired.Objects = append(spec.Targets, bundle...)
		} else {
			if *desiredPath == "" {
				return errors.New("desired required")
			}
			if err = privateJSON(*desiredPath, &desired, 4<<20); err != nil {
				return err
			}
			if desired.Objects == nil {
				return errors.New("complete desired objects required")
			}
		}
		if err = routeros.ValidateManagedDesired(desired.Instance, desired.Objects); err != nil {
			return err
		}
		current, discoverErr := client.Discover(ctx)
		if discoverErr != nil {
			return discoverErr
		}
		plan, planErr := routeros.Plan(desired.Instance, current, desired.Objects)
		if planErr != nil {
			return planErr
		}
		plan.Gate = "MANAGED: review active state, exact ownership, generated hooks and placement before apply"
		data, marshalErr := json.MarshalIndent(routerArtifact{SchemaVersion: 1, Target: url, Plan: plan, Desired: desired.Objects}, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		if err = config.WriteAtomic(*out, append(data, '\n')); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "private managed plan saved; review before router-apply")
		return nil
	}
	if action == "router-plan" {
		if *input == "" || *out == "" {
			return errors.New("config and out required")
		}
		data, err := os.ReadFile(*input)
		if err != nil {
			return errors.New("application config unavailable")
		}
		cfg, err := config.Decode(data)
		if err != nil {
			return err
		}
		foundLAN := false
		for _, iface := range caps.Interfaces {
			if iface.Name == cfg.LANInterface && !iface.Disabled {
				foundLAN = true
			}
		}
		if !foundLAN {
			return errors.New("configured LAN interface unavailable or disabled")
		}
		desired, err := routeros.Desired(cfg)
		if err != nil {
			return err
		}
		current, err := client.Discover(ctx)
		if err != nil {
			return err
		}
		plan, err := routeros.Plan(cfg.Instance, current, desired)
		if err != nil {
			return err
		}
		plan.Gate = "STAGING ONLY: disabled owned objects; dataplane activation remains blocked"
		data, err = json.MarshalIndent(routerArtifact{SchemaVersion: 1, Target: url, Plan: plan, Desired: desired}, "", "  ")
		if err != nil {
			return err
		}
		if err = config.WriteAtomic(*out, append(data, '\n')); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "private live plan saved; review before router-stage")
		return nil
	}
	if *journal == "" {
		return errors.New("journal directory required")
	}
	managed := action != "router-stage" && action != "router-reconcile" && action != "router-recover"
	var controller *routeros.Controller
	if managed {
		controller, err = routeros.NewManagedController(client, *journal)
	} else {
		controller, err = routeros.NewController(client, *journal)
	}
	if err != nil {
		return err
	}
	if action == "router-rollback" {
		return controller.Rollback(ctx)
	}
	if action == "router-cleanup" {
		if *instance == "" {
			return errors.New("instance required")
		}
		return controller.CleanupManaged(ctx, *instance)
	}
	if action == "router-recover" || action == "router-managed-recover" {
		if err = controller.Recover(ctx); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "transaction recovered")
		return nil
	}
	if *planPath == "" {
		return errors.New("reviewed plan path required")
	}
	var artifact routerArtifact
	if err = privateJSON(*planPath, &artifact, 4<<20); err != nil {
		return err
	}
	if artifact.SchemaVersion != 1 || artifact.Target != url {
		return errors.New("plan target/schema mismatch")
	}
	if action == "router-verify" {
		if artifact.Desired == nil {
			return errors.New("complete desired objects required")
		}
		return controller.Verify(ctx, artifact.Plan.Instance, artifact.Desired)
	}
	if action == "router-reconcile" || action == "router-managed-reconcile" {
		if artifact.Desired == nil {
			return errors.New("reconcile artifact requires complete desired objects")
		}
		err = controller.Reconcile(ctx, artifact.Plan.Instance, artifact.Desired)
	} else {
		if managed {
			err = controller.ApplyTransactional(ctx, artifact.Plan)
		} else {
			err = controller.Apply(ctx, artifact.Plan)
		}
	}
	if err != nil {
		return err
	}
	if managed {
		fmt.Fprintln(os.Stderr, "managed owned transaction verified")
	} else {
		fmt.Fprintln(os.Stderr, "staged disabled owned objects verified; traffic activation remains gated")
	}
	return nil
}
