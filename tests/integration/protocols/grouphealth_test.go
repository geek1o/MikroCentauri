package protocols

import (
	"context"
	"io"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/wireguard"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinnedWireGuardIsolatedHealth(t *testing.T) {
	binary := pinned(t)
	var failing atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, "protocol-data")
	}))
	defer target.Close()
	ap, ak := wgKeys(t)
	bp, bk := wgKeys(t)
	pp, pk := wgKeys(t)
	serverPort := port(t, true)
	server := wireguard.Endpoint{Name: "health-server", Enabled: true, Address: []string{"10.77.0.2/24"}, PrivateKey: bp, ListenPort: serverPort, Peers: []wireguard.Peer{{PublicKey: ak, AllowedIPs: []string{"10.77.0.1/32"}}, {PublicKey: pk, AllowedIPs: []string{"10.77.0.3/32"}}}}
	se, e := server.Build("wg-server")
	if e != nil {
		t.Fatal(e)
	}
	run(t, binary, object{"log": object{"disabled": true}, "endpoints": []any{se}, "outbounds": []any{object{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct", "rules": []any{object{"action": "route", "outbound": "direct", "override_address": "127.0.0.1"}}}}, 0)
	client, e := (wireguard.Endpoint{Name: "active-client", Enabled: true, Address: []string{"10.77.0.1/24"}, PrivateKey: ap, ListenPort: port(t, true), Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: serverPort, PublicKey: bk, AllowedIPs: []string{"0.0.0.0/0"}}}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	active, e := client.Build("active-wg")
	if e != nil {
		t.Fatal(e)
	}
	activePort := port(t, false)
	run(t, binary, object{"log": object{"disabled": true}, "endpoints": []any{active}, "inbounds": []any{object{"type": "mixed", "listen": "127.0.0.1", "listen_port": activePort}}, "route": object{"final": "active-wg"}}, activePort)
	dedicated, e := (wireguard.Endpoint{Name: "dedicated-probe", Enabled: true, Address: []string{"10.77.0.3/24"}, PrivateKey: pp, Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: serverPort, PublicKey: bk, AllowedIPs: []string{"0.0.0.0/0"}}}}).Normalize()
	if e != nil {
		t.Fatal(e)
	}
	p, e := grouphealth.NewProber(grouphealth.ProbeOptions{Binary: binary, Directory: privateDir(t), Timeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	targetURL, _ := url.Parse(target.URL)
	targetURL.Host = net.JoinHostPort("203.0.113.9", targetURL.Port())
	canary := grouphealth.Canary{URL: targetURL.String(), ExpectedStatus: 200}
	remoteUDP := *udpEcho(t)
	remoteUDP.IP = net.ParseIP("203.0.113.9")
	assertActive := func() {
		t.Helper()
		if !fetch(activePort, targetURL.String()) || !socksUDP(activePort, &remoteUDP) {
			t.Fatal("active WireGuard TCP/UDP interrupted by health peer")
		}
	}
	assertActive()
	if _, e := p.ProbeWireGuard(context.Background(), client, client, canary); e == nil {
		t.Fatal("same-key probe accepted")
	}

	first, e := p.ProbeWireGuard(context.Background(), client, dedicated, canary)
	if e != nil || !first.Available || first.EndpointID != client.ID || first.LastSuccess.IsZero() {
		t.Fatal("real WireGuard health did not succeed", e)
	}
	assertActive()
	failing.Store(true)
	last, e := p.ProbeWireGuard(context.Background(), client, dedicated, canary)
	if e == nil || last.Available || last.LastFailure.IsZero() || last.LastSuccess != first.LastSuccess {
		t.Fatal("failure observation lost prior WireGuard health")
	}
	failing.Store(false)
	assertActive()
	_, wrong := wgKeys(t)
	client.Peers[0].PublicKey = wrong
	dedicated.Peers[0].PublicKey = wrong
	dedicated.ID = ""
	dedicated, e = dedicated.Normalize()
	if e != nil {
		t.Fatal(e)
	}
	client.ID = ""
	client, e = client.Normalize()
	if e != nil {
		t.Fatal(e)
	}
	if observation, e := p.ProbeWireGuard(context.Background(), client, dedicated, canary); e == nil || observation.Available {
		t.Fatal("wrong WireGuard peer key passed health through bypass")
	}
	assertActive()
}
