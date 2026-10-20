// mc-node-check checks a private API draft through isolated proxy processes.
// It never opens a RouterOS connection or activates the draft.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mikrocentauri.local/core/internal/health"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/grouphealth"
)

type result struct {
	ID            string `json:"id"`
	Protocol      string `json:"protocol"`
	Success       bool   `json:"success"`
	LatencyMS     int64  `json:"latency_ms"`
	Failure       string `json:"failure,omitempty"`
	EgressIP      string `json:"egress_ip,omitempty"`
	FailureDetail string `json:"failure_detail,omitempty"`
}
type report struct {
	Scope        string    `json:"scope"`
	CheckedAt    time.Time `json:"checked_at"`
	RoutingReady bool      `json:"routing_ready"`
	Results      []result  `json:"results"`
}

func readDraft(path string) (coreconfig.Model, error) {
	var empty coreconfig.Model
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return empty, errors.New("absolute private draft required")
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return empty, errors.New("private draft unavailable or contains symlink")
	}
	parent, e := os.Stat(filepath.Dir(path))
	if e != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return empty, errors.New("draft directory must be private 0700")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return empty, errors.New("private draft unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 4<<20 {
		return empty, errors.New("draft must be bounded regular 0600 file")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if e != nil || len(b) > 4<<20 {
		return empty, errors.New("private draft read failed")
	}
	var envelope struct {
		Version int              `json:"version"`
		Model   coreconfig.Model `json:"model"`
	}
	if json.Unmarshal(b, &envelope) != nil || envelope.Version != 1 || envelope.Model.Validate() != nil {
		return empty, errors.New("invalid private API draft")
	}
	if len(envelope.Model.Endpoints) == 0 || len(envelope.Model.Endpoints) > 128 || len(envelope.Model.WireGuard) > 0 {
		return empty, errors.New("draft requires 1..128 proxy endpoints and no WireGuard peers")
	}
	return envelope.Model, nil
}
func run(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mc-node-check", flag.ContinueOnError)
	direct := fs.Bool("direct-only", false, "observe a verified direct HTTPS egress without reading a draft")
	status := fs.Int("status", 204, "expected HTTP status")
	format := fs.String("response-format", "", "optional remote_ip_json or cloudflare_trace peer response")
	draft := fs.String("draft", "", "absolute private API draft path")
	nodeID := fs.String("node", "", "check one endpoint ID from the private draft")
	dir := fs.String("state", "", "dedicated private temporary probe directory")
	binary := fs.String("sing-box", "/usr/bin/sing-box", "pinned proxy executable")
	target := fs.String("url", "https://www.gstatic.com/generate_204", "public HTTPS test URL without credentials or query")
	parallel := fs.Int("concurrency", 2, "parallel checks, 1..4")
	timeout := fs.Duration("timeout", 10*time.Second, "per-node timeout, at most 30s")
	if e := fs.Parse(args); e != nil {
		return e
	}
	u, e := url.Parse(*target)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || *parallel < 1 || *parallel > 4 || *timeout <= 0 || *timeout > 30*time.Second || fs.NArg() != 0 || (!*direct && *dir == "") || *status < 200 || *status > 299 || (*format != "" && *format != health.CanaryRemoteIPJSON && *format != health.CanaryCloudflareTrace) {
		return errors.New("invalid isolated probe options")
	}
	if *direct {
		if *format == "" {
			return errors.New("direct observation requires a peer response format")
		}
		started := time.Now()
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: 16 << 10}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, *target, nil)
		if err != nil {
			return errors.New("direct probe request invalid")
		}
		response, err := client.Do(req)
		if err != nil {
			return errors.New("direct verified HTTPS probe failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
		if err != nil || response.StatusCode != *status {
			return errors.New("direct probe response failed")
		}
		ip, err := health.ParseCanaryIP(body, *format)
		if err != nil {
			return errors.New("direct probe peer response invalid")
		}
		return json.NewEncoder(out).Encode(report{Scope: "direct verified HTTPS egress observation; no routing activation", CheckedAt: time.Now().UTC(), Results: []result{{ID: "direct-control", Protocol: "direct", Success: true, LatencyMS: time.Since(started).Milliseconds(), EgressIP: ip.String()}}})
	}
	m, e := readDraft(*draft)
	if e != nil {
		return e
	}
	if *nodeID != "" {
		found := false
		for _, ep := range m.Endpoints {
			if ep.ID == *nodeID {
				m.Endpoints = []endpoints.Endpoint{ep}
				found = true
				break
			}
		}
		if !found {
			return errors.New("requested node absent from draft")
		}
	}
	p, e := grouphealth.NewProber(grouphealth.ProbeOptions{Binary: *binary, Directory: *dir, Bootstrap: m.DNS.Bootstrap, Timeout: *timeout, Concurrency: *parallel, FailureDiagnostics: true})
	if e != nil {
		return errors.New("isolated prober unavailable")
	}
	r := report{Scope: "isolated HTTPS through draft endpoints; no RouterOS or LAN steering; latency excludes process startup", CheckedAt: time.Now().UTC(), Results: make([]result, len(m.Endpoints))}
	var wg sync.WaitGroup
	defer wg.Wait()
	sem := make(chan struct{}, *parallel)
	for i, ep := range m.Endpoints {
		if !ep.Enabled {
			r.Results[i] = result{ID: ep.ID, Protocol: ep.Protocol, Failure: "endpoint_disabled"}
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return errors.New("probe interrupted")
		}
		wg.Go(func() {
			defer func() { <-sem }()
			v, err := p.Probe(ctx, ep, grouphealth.Canary{URL: *target, ExpectedStatus: *status, ResponseFormat: *format})
			r.Results[i] = result{ID: ep.ID, Protocol: ep.Protocol, Success: err == nil, LatencyMS: v.Latency.Milliseconds(), Failure: v.Failure, EgressIP: v.EgressIP, FailureDetail: v.FailureDetail}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return errors.New("probe interrupted")
	}
	return json.NewEncoder(out).Encode(r)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
