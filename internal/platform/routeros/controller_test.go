//go:build linux || darwin

package routeros

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newControllerFixture(t *testing.T, m *mockRouter, wrapper func(http.Handler) http.Handler) (*LabController, *Client, string) {
	t.Helper()
	var h http.Handler = m
	if wrapper != nil {
		h = wrapper(h)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c, e := NewLabClient(s.URL+"/rest", "lab", "test-password", s.Client())
	if e != nil {
		t.Fatal(e)
	}
	d := filepath.Join(t.TempDir(), "private")
	ctrl, e := NewLabController(c, d)
	if e != nil {
		t.Fatal(e)
	}
	return ctrl, c, d
}
func controllerPlan(t *testing.T, c *Client, want []Object) ChangePlan {
	t.Helper()
	rows, e := c.Discover(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	p, e := Plan("lab", rows, want)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestDurableControllerCrashAfterCreateRecoversOwnedOnly(t *testing.T) {
	m := &mockRouter{objects: []Object{{Path: "ip/route", ID: "*USER", Fields: map[string]string{"comment": "user route"}}}}
	ctrl, c, d := newControllerFixture(t, m, nil)
	p := controllerPlan(t, c, fixture(t))
	crash := errors.New("simulated process crash")
	ctrl.fault = func(boundary string) error {
		if boundary == "after-mutation" {
			return crash
		}
		return nil
	}
	if e := ctrl.Apply(context.Background(), p); !errors.Is(e, crash) {
		t.Fatalf("crash %v", e)
	}
	b, e := os.ReadFile(filepath.Join(d, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "test-password") {
		t.Fatal("credentials persisted")
	}
	s, _ := os.Stat(filepath.Join(d, "journal.json"))
	if s.Mode().Perm() != 0600 {
		t.Fatal("journal permissions")
	}
	reboot, e := NewLabController(c, d)
	if e != nil {
		t.Fatal(e)
	}
	if e = reboot.Apply(context.Background(), p); e == nil {
		t.Fatal("accepted pending transaction")
	}
	if e = reboot.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(m.objects) != 1 || m.objects[0].ID != "*USER" {
		t.Fatalf("wrong cleanup %+v", m.objects)
	}
	if e = reboot.Recover(context.Background()); e != nil {
		t.Fatal("non idempotent recovery")
	}
}
func TestDurableControllerDroppedResponseDiscoversSuccessfulWrite(t *testing.T) {
	m := &mockRouter{}
	once := false
	wrapper := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" && !once {
				once = true
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				conn, _, e := w.(http.Hijacker).Hijack()
				if e != nil {
					t.Fatal(e)
				}
				conn.Close()
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	ctrl, c, _ := newControllerFixture(t, m, wrapper)
	if e := ctrl.Apply(context.Background(), controllerPlan(t, c, fixture(t))); e != nil {
		t.Fatal(e)
	}
	if len(m.objects) != 3 {
		t.Fatal("lost or duplicate create")
	}
}
func TestDurableControllerRecoveryRefusesExternalEdit(t *testing.T) {
	m := &mockRouter{}
	ctrl, c, _ := newControllerFixture(t, m, nil)
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, fixture(t))) == nil {
		t.Fatal("missing crash")
	}
	m.objects[0].Fields["to-addresses"] = "192.0.2.66"
	if e := ctrl.Recover(context.Background()); e == nil {
		t.Fatal("overwrote external edit")
	}
	if m.objects[0].Fields["to-addresses"] != "192.0.2.66" {
		t.Fatal("external state lost")
	}
}
func TestDurableControllerRecoversUpdateAndDeleteWithoutReadOnlyWrites(t *testing.T) {
	for _, action := range []string{"update", "delete"} {
		t.Run(action, func(t *testing.T) {
			original := Object{Path: "ip/route", ID: "*A", Fields: map[string]string{"comment": "mikrocentauri:lab:route:one", "disabled": "true", "dst-address": "198.18.0.0/15", "gateway": "172.30.0.2", "active": "false", "dynamic": "false", "static": "true", "immediate-gw": "172.30.0.2%veth"}}
			m := &mockRouter{objects: []Object{original}}
			ctrl, c, _ := newControllerFixture(t, m, nil)
			var desired []Object
			if action == "update" {
				o := controllerProjection(original)
				o.ID = ""
				o.Fields["disabled"] = "false"
				desired = []Object{o}
			}
			ctrl.fault = func(b string) error {
				if b == "after-mutation" {
					return errors.New("crash")
				}
				return nil
			}
			if ctrl.Apply(context.Background(), controllerPlan(t, c, desired)) == nil {
				t.Fatal("missing crash")
			}
			if e := ctrl.Recover(context.Background()); e != nil {
				t.Fatal(e)
			}
			if len(m.objects) != 1 || !controllerSame(m.objects[0], original) {
				t.Fatalf("not restored %+v", m.objects)
			}
			if action == "delete" {
				if _, ok := m.objects[0].Fields["immediate-gw"]; ok {
					t.Fatal("runtime field replayed")
				}
			}
		})
	}
}
func TestDurableControllerSerializesAndRejectsWritableInjection(t *testing.T) {
	ctrl, c, d := newControllerFixture(t, &mockRouter{}, nil)
	release, e := ctrl.lock()
	if e != nil {
		t.Fatal(e)
	}
	other, e := NewLabController(c, d)
	if e != nil {
		t.Fatal(e)
	}
	if other.Recover(context.Background()) == nil {
		t.Fatal("concurrent writer accepted")
	}
	release()
	want := fixture(t)
	want[0].Fields["password"] = "secret"
	if ctrl.Apply(context.Background(), controllerPlan(t, c, want)) == nil {
		t.Fatal("writable injection")
	}
	if _, e = os.Stat(filepath.Join(d, "journal.json")); !os.IsNotExist(e) {
		t.Fatal("invalid request persisted")
	}
}
func TestDurableControllerNeverAcceptsUnrealizedSuccess(t *testing.T) {
	m := &mockRouter{}
	wrapper := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				w.Write([]byte(`{".id":"*NOT-REAL"}`))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	ctrl, c, _ := newControllerFixture(t, m, wrapper)
	if ctrl.Apply(context.Background(), controllerPlan(t, c, fixture(t))) == nil {
		t.Fatal("trusted success response without state")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
}

func TestDurableControllerRestoresAbsentFieldAndRejectsOrderedDeletion(t *testing.T) {
	original := Object{Path: "ip/route", ID: "*A", Fields: map[string]string{"comment": "mikrocentauri:lab:route:one", "dst-address": "198.18.0.0/15", "gateway": "172.30.0.2"}}
	m := &mockRouter{objects: []Object{original}}
	ctrl, c, _ := newControllerFixture(t, m, nil)
	desired := controllerProjection(original)
	desired.ID = ""
	desired.Fields["pref-src"] = "192.0.2.1"
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, []Object{desired})) == nil {
		t.Fatal("missing crash")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	m2 := &mockRouter{objects: []Object{{Path: "ip/firewall/nat", ID: "*N", Fields: map[string]string{"comment": "mikrocentauri:lab:nat:one", "chain": "dstnat", "action": "accept"}}}}
	ctrl2, c2, _ := newControllerFixture(t, m2, nil)
	if ctrl2.Apply(context.Background(), controllerPlan(t, c2, nil)) == nil {
		t.Fatal("accepted ordered deletion")
	}
	if m2.mutations != 0 {
		t.Fatal("mutated firewall before placement gate")
	}
}
