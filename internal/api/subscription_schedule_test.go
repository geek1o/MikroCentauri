package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubscriptionScheduleHTTPDurabilityAndStrictInput(t *testing.T) {
	registry, manager, _ := workflowRegistry(t)
	s, _, token := setup(t, nil)
	s.opts.Subscriptions = registry
	for _, raw := range []string{`{}`, `{"interval_seconds":null}`, `{"interval_seconds":59}`, `{"interval_seconds":86401}`, `{"interval_seconds":60,"url":"https://evil.example"}`, `{"interval_seconds":60,"interval_seconds":0}`} {
		if w := call(s, "POST", "/api/v1/subscriptions/schedule", token, raw); w.Code != 400 {
			t.Fatal(raw, w.Code, w.Body.String())
		}
	}
	if w := call(s, "POST", "/api/v1/subscriptions/schedule", token, `{"interval_seconds":120}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if manager.refreshes != 0 || s.draft != nil {
		t.Fatal("schedule refreshed/imported/applied immediately")
	}
	path := filepath.Join(registry.dir, "subscription-schedule.json")
	fi, e := os.Stat(path)
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("schedule privacy", e)
	}
	dir := registry.dir
	registry.Close()
	reopened, e := NewSubscriptionResources(dir, manager)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if e = reopened.InitializeSchedule(time.Hour); e != nil {
		t.Fatal(e)
	}
	v, e := reopened.Schedule()
	if e != nil || v.IntervalSeconds != 120 || v.Running {
		t.Fatal(v, e)
	}
	if w := call(s, "POST", "/api/v1/subscriptions/schedule", "", `{"interval_seconds":0}`); w.Code != 401 {
		t.Fatal("unauthenticated schedule")
	}
}

func TestSubscriptionScheduleOwnerDisabledCancellationAndNoImmediateFetch(t *testing.T) {
	registry, manager, _ := workflowRegistry(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- registry.RunScheduled(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		v, e := registry.Schedule()
		if e != nil {
			t.Fatal(e)
		}
		if v.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owner not started")
		}
		time.Sleep(time.Millisecond)
	}
	if e := registry.RunScheduled(ctx); e == nil {
		t.Fatal("duplicate owner")
	}
	if _, e := registry.SetSchedule(60); e != nil {
		t.Fatal(e)
	}
	if _, e := registry.SetSchedule(0); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("disabled owner did not stop")
	}
	v, e := registry.Schedule()
	if e != nil || v.Running || v.IntervalSeconds != 0 || manager.refreshes != 0 {
		t.Fatal(v, e, "unexpected immediate network fetch")
	}
}
