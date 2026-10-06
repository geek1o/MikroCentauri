package coreactivation

import (
	"context"
	"reflect"
	"testing"
)

func TestAPIModelValidationDoesNotReserveOrReplaceChild(t *testing.T) {
	o, store, ledger, _ := transitionFixture(t)
	c, e := NewTransition(o)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	if _, e = c.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	before := c.Status()
	bindings := ledger.Mappings()
	model, e := c.CurrentModel()
	if e != nil {
		t.Fatal(e)
	}
	model.DNS.SelectedDomains = []string{"selected.test", "added.test"}
	if e = c.ValidateModel(context.Background(), before.Namespace.Revision, model); e != nil {
		t.Fatal(e)
	}
	after := c.Status()
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(bindings, ledger.Mappings()) {
		t.Fatal("API preview changed active state")
	}
	actual, _ := store.Snapshot()
	if actual.Pending != nil {
		t.Fatal("preview reserved namespace")
	}
	if e = c.ValidateModel(context.Background(), before.Namespace.Revision-1, model); e == nil || c.Status().Process.PID != before.Process.PID {
		t.Fatal("stale preview disturbed child")
	}
	current, e := c.CurrentModel()
	if e != nil || reflect.DeepEqual(current.DNS.SelectedDomains, model.DNS.SelectedDomains) {
		t.Fatal("mutable model view")
	}
}
