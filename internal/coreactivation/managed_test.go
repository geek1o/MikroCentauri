package coreactivation

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/grouphealth"
	"mikrocentauri.local/core/internal/supervisor"
)

func TestManagedHealthSwitchStopRecoverAndStage(t *testing.T) {
	o, _, ledger, _, barrier := setup(t)
	model := fixtureModel(t)
	ep, err := endpoints.ParseURI("ss://aes-256-gcm:public-fixture@127.0.0.1:8389#secondary")
	if err != nil {
		t.Fatal(err)
	}
	model.Endpoints = append(model.Endpoints, ep)
	first := model.Endpoints[0].ID
	model.Groups = []coreconfig.Group{{ID: "manual", Type: "fallback", Members: []string{first, ep.ID}}}
	healthy := map[string]bool{first: true, ep.ID: true}
	probes := 0
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManaged(context.Background(), ManagedOptions{Activation: o, Model: model, GroupID: "manual", Process: supervisor.Options{Binary: binary, Directory: privateDir(t), Validator: func(context.Context, string) error { return nil }, ReadyTimeout: time.Second, StopTimeout: 100 * time.Millisecond}, Probe: func(ctx context.Context, node endpoints.Endpoint) (grouphealth.Observation, error) {
		probes++
		now := time.Now().UTC()
		obs := grouphealth.Observation{EndpointID: node.ID, CheckedAt: now, Health: coreconfig.Health{Available: healthy[node.ID], Latency: time.Millisecond}}
		if healthy[node.ID] {
			obs.LastSuccess = now
			return obs, nil
		}
		obs.LastFailure = now
		return obs, errors.New("fixture canary failed")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if m.Status().Ready || !barrier.quarantined.Load() {
		t.Fatal("disk-only startup became ready")
	}
	if err = m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Ready || m.Status().Group.Selected != first {
		t.Fatal("fresh primary did not activate")
	}
	healthy[first] = false
	if err = m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Ready || m.Status().Group.Selected != ep.ID {
		t.Fatal("secondary did not activate through supervised admission")
	}
	healthy[ep.ID] = false
	if err = m.Tick(context.Background()); err == nil {
		t.Fatal("all failed nodes reported ready")
	}
	if m.Status().Ready || m.Status().Process.Live || !barrier.quarantined.Load() {
		t.Fatal("all failed nodes left child or gates open")
	}
	healthy[ep.ID] = true
	if err = m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Ready || m.Status().Group.Selected != ep.ID {
		t.Fatal("fresh fallback recovery failed")
	}
	before := probes
	model.Instance = "updated"
	if err = m.UpdateModel(context.Background(), model); err != nil {
		t.Fatal(err)
	}
	if probes != before || m.Status().Ready || m.Status().Process.Live || !barrier.quarantined.Load() {
		t.Fatal("unobserved model applied before fresh probe")
	}
	if err = m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probes <= before || !m.Status().Ready {
		t.Fatal("staged policy did not probe then activate")
	}
	// Healthy endpoints cannot conceal a failed RouterOS/backend readback.
	ledger.fail.Store(true)
	if err = m.Tick(context.Background()); err == nil || m.Status().Ready || m.Status().Process.Live || !barrier.quarantined.Load() {
		t.Fatal("healthy canaries concealed backend verification outage")
	}
	ledger.fail.Store(false)
	if err = m.Tick(context.Background()); err != nil || !m.Status().Ready {
		t.Fatal("runtime proof did not recover after fresh backend verification", err)
	}
	models, err := os.ReadDir(o.Directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, file := range models {
		if len(file.Name()) > len(".model.json") && file.Name()[len(file.Name())-len(".model.json"):] == ".model.json" {
			count++
		}
	}
	if count > 5 {
		t.Fatal("managed runtime retained unbounded source model revisions")
	}
	if err = m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = m.Tick(context.Background()); err == nil {
		t.Fatal("closed managed runtime resumed")
	}
}
