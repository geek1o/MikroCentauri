package coreactivation

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/supervisor"
	"mikrocentauri.local/core/internal/wireguard"
)

func TestManagedWireGuardRequiresActualCurrentPath(t *testing.T) {
	o, _, _, _, barrier := setup(t)
	model := fixtureModel(t)
	private := make([]byte, 32)
	peer := make([]byte, 32)
	for i := range private {
		private[i] = 1
		peer[i] = 2
	}
	remote, _ := ecdh.X25519().NewPrivateKey(peer)
	ep, err := (wireguard.Endpoint{Enabled: true, Address: []string{"10.77.0.1/32"}, PrivateKey: base64.StdEncoding.EncodeToString(private), Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: 59999, PublicKey: base64.StdEncoding.EncodeToString(remote.PublicKey().Bytes()), AllowedIPs: []string{"0.0.0.0/0"}}}}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	model.Endpoints = nil
	model.WireGuard = []wireguard.Endpoint{ep}
	model.Groups = []coreconfig.Group{{ID: "manual", Type: "fallback", Members: []string{ep.ID}}}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	opts := ManagedOptions{Activation: o, Model: model, GroupID: "manual", TickTimeout: time.Second, Process: supervisor.Options{Binary: binary, Directory: privateDir(t), Validator: func(context.Context, string) error { return nil }, ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond}, ProbeWireGuard: func(ctx context.Context, node wireguard.Endpoint) (grouphealth.Observation, error) {
		now := time.Now().UTC()
		return grouphealth.Observation{EndpointID: node.ID, CheckedAt: now, Health: coreconfig.Health{Available: true, LastSuccess: now, Latency: time.Millisecond}}, nil
	}}
	if _, err = NewManaged(context.Background(), opts); err == nil {
		t.Fatal("missing active-path probe accepted")
	}
	failed := false
	calls := 0
	opts.ProbeCurrent = func(ctx context.Context) error {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded active-path probe")
		}
		if failed {
			return errors.New("fixture active key unauthorized")
		}
		return nil
	}
	m, err := NewManaged(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if err = m.Tick(context.Background()); err != nil || !m.Status().Ready || calls != 1 {
		t.Fatal("fresh active path did not activate", err)
	}
	failed = true
	if err = m.Tick(context.Background()); err == nil || m.Status().Ready || m.Status().Process.Live || !barrier.quarantined.Load() {
		t.Fatal("dedicated peer health concealed active path failure", err)
	}
	if m.group.Observations()[ep.ID].LastSuccess.IsZero() {
		t.Fatal("provider health history lost")
	}
	failed = false
	if err = m.Tick(context.Background()); err != nil || !m.Status().Ready {
		t.Fatal("fresh active path did not recover", err)
	}
}
