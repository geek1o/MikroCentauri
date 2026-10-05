//go:build linux || darwin

package routeros

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func managedFixture(t *testing.T, m *mockRouter) (*Controller, *Client) {
	t.Helper()
	s := httptest.NewTLSServer(m)
	t.Cleanup(s.Close)
	client, err := NewClient(s.URL+"/rest", "lab", "test-password", s.Client())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewManagedController(client, filepath.Join(directory, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	return c, client
}
func TestManagedActiveApplyVerifyRollbackAndCleanup(t *testing.T) {
	m := &mockRouter{objects: []Object{{Path: "ip/route", ID: "*USER", Fields: map[string]string{"comment": "user"}}}}
	c, client := managedFixture(t, m)
	ctx := context.Background()
	desired := []Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab:route:active", "disabled": "false", "dst-address": "203.0.113.0/24", "gateway": "192.0.2.1"}}}
	p := controllerPlan(t, client, desired)
	if err := c.ApplyTransactional(ctx, p); err != nil {
		t.Fatal(err)
	}
	mutations := m.mutations
	if err := c.ApplyTransactional(ctx, p); err != nil {
		t.Fatal(err)
	}
	if m.mutations != mutations {
		t.Fatal("repeated reviewed apply mutated state")
	}
	if err := c.Verify(ctx, "lab", desired); err != nil {
		t.Fatal(err)
	}
	if err := c.ApplyTransactional(ctx, controllerPlan(t, client, desired)); err != nil {
		t.Fatal(err)
	}
	if len(m.objects) != 2 {
		t.Fatal("non-idempotent apply")
	}
	// An empty idempotent transaction has nothing to compensate. Make a real update.
	desired[0].Fields["gateway"] = "192.0.2.2"
	if err := c.ApplyTransactional(ctx, controllerPlan(t, client, desired)); err != nil {
		t.Fatal(err)
	}
	if err := c.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if m.objects[1].Fields["gateway"] != "192.0.2.1" {
		t.Fatal("did not restore")
	}
	if err := c.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.CleanupManaged(ctx, "lab"); err != nil {
		t.Fatal(err)
	}
	if len(m.objects) != 1 || m.objects[0].ID != "*USER" {
		t.Fatal("cleanup touched user")
	}
}
func TestManagedFailureCompensatesAndHooksRejectBeforeMutation(t *testing.T) {
	m := &mockRouter{}
	c, client := managedFixture(t, m)
	want := fixture(t)
	m.failAt = 2
	if err := c.Apply(context.Background(), controllerPlan(t, client, want)); err == nil {
		t.Fatal("missing failure")
	}
	if len(m.objects) != 0 {
		t.Fatal("failure did not compensate")
	}
	bad := Object{Path: "tool/netwatch", Fields: map[string]string{"comment": "mikrocentauri:lab:netwatch:readiness", "disabled": "false", "host": "192.0.2.1", "test-script": "/ip/firewall/filter/remove [find]"}}
	before := m.mutations
	p, _ := Plan("lab", nil, []Object{bad})
	if err := c.ApplyTransactional(context.Background(), p); err == nil {
		t.Fatal("accepted arbitrary hook")
	}
	if m.mutations != before {
		t.Fatal("mutated before hook rejection")
	}
}
func TestManagedRollbackPreservesExternalEdit(t *testing.T) {
	m := &mockRouter{}
	c, client := managedFixture(t, m)
	want := fixture(t)
	if err := c.ApplyTransactional(context.Background(), controllerPlan(t, client, want)); err != nil {
		t.Fatal(err)
	}
	m.objects[0].Fields["to-addresses"] = "192.0.2.99"
	if err := c.Rollback(context.Background()); err == nil {
		t.Fatal("accepted external edit")
	}
	if m.objects[0].Fields["to-addresses"] != "192.0.2.99" {
		t.Fatal("external edit lost")
	}
}
