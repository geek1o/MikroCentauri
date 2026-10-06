package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/realdns"
	"mikrocentauri.local/core/internal/singbox"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Diagnose only runs fixed composition-owned targets. It does not mutate
// policies, reconcile leases, toggle readiness or probe arbitrary
// nodes/URLs. TCP DNS queries use the configured gateway and first active name,
// following its ordinary publication proof if an answer requires a new alias.
func (r *Runtime) Diagnose(ctx context.Context, kind string) error {
	return r.Host.Inspect(ctx, func(ctx context.Context) error {
		switch kind {
		case "dns":
			m, e := r.Model()
			if e != nil {
				return e
			}
			if len(m.DNS.SelectedDomains) == 0 {
				return errors.New("active DNS name unavailable")
			}
			resolver, e := realdns.New(realdns.Config{Address: r.Profile.DNSListen, Timeout: 3 * time.Second})
			if e != nil {
				return e
			}
			answers, _, e := resolver.ResolveA(ctx, m.DNS.SelectedDomains[0])
			if e != nil {
				return e
			}
			if len(answers) == 0 {
				return errors.New("DNS has no IPv4 answer")
			}
			return nil
		case "direct":
			return directCanary(ctx, r.Profile.CanaryURL)
		case "proxy", "routing", "watchdog":
			probe := r.diagnosticProbes[kind]
			if probe == nil {
				return errors.New("diagnostic adapter unavailable")
			}
			return probe(ctx)
		default:
			return errors.New("unsupported diagnostic")
		}
	})
}
func directCanary(ctx context.Context, target string) error {
	// Target is the already validated literal-IP operator profile. No environment
	// proxy, redirects, resolver, API parameters or connection reuse is involved.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return canaryRequest(ctx, client, target)
}
func canaryRequest(ctx context.Context, client *http.Client, target string) error {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if e != nil {
		return errors.New("invalid direct canary")
	}
	response, e := client.Do(req)
	if e != nil {
		return errors.New("direct canary transport failed")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || len(body) > 4096 || response.StatusCode != 200 {
		return errors.New("direct canary response invalid")
	}
	var peer struct {
		RemoteIP string `json:"remote_ip"`
	}
	if json.Unmarshal(body, &peer) != nil {
		return errors.New("direct canary response invalid")
	}
	ip, e := netip.ParseAddr(peer.RemoteIP)
	if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("direct canary peer invalid")
	}
	return nil
}

// SingBoxVersion observes only the first version line from the fixed private
// binary, with bounded time and output. Raw command output is never an API view.
func (r *Runtime) SingBoxVersion(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, r.binary, "version")
	output := &boundedVersionOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	if command.Run() != nil {
		return "", errors.New("version unavailable")
	}
	first, _, _ := strings.Cut(output.String(), "\n")
	if first != "sing-box version "+singbox.Version {
		return "", errors.New("unexpected binary version")
	}
	return singbox.Version, nil
}

type boundedVersionOutput struct{ bytes.Buffer }

func (b *boundedVersionOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, errors.New("version output exceeds bound")
	}
	return b.Buffer.Write(p)
}
