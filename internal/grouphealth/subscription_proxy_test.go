package grouphealth

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/subscriptions"
)

func TestSubscriptionDownloadThroughRealIsolatedProxyPreservesTLSAndLKG(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY for actual isolated source downloads")
	}
	var hits atomic.Int32
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("trojan://fixture-private-password@example.com:443#downloaded"))
	}))
	defer source.Close()
	roots := x509.NewCertPool()
	roots.AddCert(source.Certificate())
	port := availablePort(t)
	stop := ssServer(t, binary, port, "download-ss-password")
	ep, _ := endpoints.ParseURI("ss://aes-256-gcm:download-ss-password@127.0.0.1:" + strconv.Itoa(int(port)))
	parent := privateDir(t)
	probeDir := filepath.Join(parent, "children")
	p, err := NewProber(ProbeOptions{Binary: binary, Directory: probeDir, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	m, err := subscriptions.New(filepath.Join(parent, "source-cache"), subscriptions.Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	spec := subscriptions.Spec{ID: "source", URL: source.URL + "/private-source-token", ProxyNode: ep.ID}
	refresh := func() (subscriptions.State, error) {
		var state subscriptions.State
		err := p.WithEndpointProxy(context.Background(), ep, func(ctx context.Context, proxy *url.URL) error {
			dial, err := subscriptions.HTTPProxyDialer(proxy)
			if err != nil {
				return err
			}
			state, err = m.RefreshVia(ctx, spec, dial)
			return err
		})
		return state, err
	}
	first, err := refresh()
	if err != nil || len(first.Nodes) != 1 || first.Failure != "" || hits.Load() != 1 {
		t.Fatal("verified source download failed", err)
	}
	children, err := os.ReadDir(probeDir)
	if err != nil || len(children) != 0 {
		t.Fatal("isolated child state retained")
	}
	// A selected dead proxy must not silently retry the reachable source directly.
	stop()
	last, err := refresh()
	if err == nil || hits.Load() != 1 || len(last.Nodes) != 1 || last.LastSuccess != first.LastSuccess {
		t.Fatal("direct fallback or lost last-good cache", err, hits.Load())
	}
	if len(p.observations) != 0 {
		t.Fatal("source download became an endpoint health observation")
	}
	// Ordinary Refresh refuses the explicitly proxied spec rather than dialing.
	last, err = m.Refresh(context.Background(), spec)
	if err == nil || last.FailureCode != "proxy_unavailable" || hits.Load() != 1 {
		t.Fatal("missing proxy bypassed selection")
	}
}
