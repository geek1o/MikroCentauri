package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimeHistoryRecordsVerifiedRecoveryAndFailedCurrentCanary(t *testing.T) {
	h, _, fail := newTestHost(t)
	if len(h.Events()) != 0 {
		t.Fatal("startup invented ready history")
	}
	if e := h.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	events := h.Events()
	if len(events) != 2 || events[0].Event != "recovery_started" || events[0].Level != "warning" || events[1].Event != "recovery_verified" || events[1].Level != "info" || events[1].ConfigRevision != 1 {
		t.Fatal(events)
	}
	fail.Store(true)
	if h.Tick(context.Background()) == nil || h.View().Ready {
		t.Fatal("failed current proof kept admission")
	}
	events = h.Events()
	if events[len(events)-2].Event != "canary_failed" || events[len(events)-1].Event != "readiness_withdrawn" || events[len(events)-1].Level != "warning" {
		t.Fatal("fail-open missing from history", events)
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), "bad active path") || strings.Contains(string(raw), "secret-password") {
		t.Fatal("dependency error exposed", string(raw))
	}
	fail.Store(false)
	if h.Recover(context.Background()) != nil || !h.View().Ready {
		t.Fatal("recovery not verified")
	}
	if h.Apply(context.Background(), 1, fixture(t)) != nil {
		t.Fatal("apply failed")
	}
	events = h.Events()
	if events[len(events)-1].Event != "apply_verified" || events[len(events)-1].ConfigRevision != 2 {
		t.Fatal(events)
	}
	events[0].Event = "caller-mutation"
	if h.Events()[0].Event == "caller-mutation" {
		t.Fatal("mutable history exposed")
	}
}
func TestRuntimeHistoryBoundsPersistentRecoveryFailures(t *testing.T) {
	h, _, fail := newTestHost(t)
	fail.Store(true)
	for i := 0; i < 140; i++ {
		if h.Recover(context.Background()) == nil {
			t.Fatal("failed canary recovery accepted")
		}
	}
	events := h.Events()
	if len(events) != 128 {
		t.Fatal("unbounded runtime history", len(events))
	}
	for _, event := range events {
		if event.Component != "runtime" || event.RequestID != "" || event.Level != "warning" || event.ConfigRevision != 1 || event.Timestamp.IsZero() {
			t.Fatal("invalid structured lifecycle event", event)
		}
	}
}
