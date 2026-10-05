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
	"syscall"
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
	temp, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	d := filepath.Join(temp, "private")
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

func stagedControllerFixture(t *testing.T, m *mockRouter) (*Controller, *Client, string) {
	t.Helper()
	s := httptest.NewTLSServer(m)
	t.Cleanup(s.Close)
	client, err := NewClient(s.URL+"/rest", "lab", "test-password", s.Client())
	if err != nil {
		t.Fatal(err)
	}
	temp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(temp, "journal")
	ctrl, err := NewController(client, dir)
	if err != nil {
		t.Fatal(err)
	}
	return ctrl, client, dir
}

func TestStagedControllerRejectsCleartextAndActiveMutations(t *testing.T) {
	_, lab, dir := newControllerFixture(t, &mockRouter{}, nil)
	if _, err := NewController(lab, dir); err == nil {
		t.Fatal("cleartext accepted")
	}
	for _, action := range []string{"create", "update-before", "update-after", "delete"} {
		t.Run(action, func(t *testing.T) {
			m := &mockRouter{}
			ctrl, client, _ := stagedControllerFixture(t, m)
			desired := fixture(t)[:1]
			desired[0].Fields["disabled"] = "true"
			if action != "create" {
				current := controllerProjection(desired[0])
				current.ID = "*A"
				if action == "update-before" || action == "delete" {
					current.Fields["disabled"] = "false"
				}
				m.objects = []Object{current}
			}
			switch action {
			case "create", "update-after":
				desired[0].Fields["disabled"] = "false"
			case "update-before":
				desired[0].Fields["to-addresses"] = "192.0.2.88"
			case "delete":
				desired = nil
			}
			plan := controllerPlan(t, client, desired)
			if err := ctrl.Apply(context.Background(), plan); err == nil {
				t.Fatal("active state accepted")
			}
			if m.mutations != 0 {
				t.Fatal("mutation before staging gate")
			}
		})
	}
}

func TestStagedControllerReconcileRecoversBeforeFreshPlan(t *testing.T) {
	m := &mockRouter{objects: []Object{{Path: "ip/route", ID: "*USER", Fields: map[string]string{"comment": "user route"}}}}
	ctrl, client, dir := stagedControllerFixture(t, m)
	crash := errors.New("crash")
	ctrl.fault = func(boundary string) error {
		if boundary == "after-mutation" {
			return crash
		}
		return nil
	}
	if err := ctrl.Reconcile(context.Background(), "lab", fixture(t)); !errors.Is(err, crash) {
		t.Fatal(err)
	}
	reopened, err := NewController(client, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Reconcile(context.Background(), "lab", fixture(t)); err != nil {
		t.Fatal(err)
	}
	if len(m.objects) != 4 {
		t.Fatalf("unexpected objects %+v", m.objects)
	}
	if m.objects[0].ID != "*USER" {
		t.Fatal("unowned object modified")
	}
	mutations := m.mutations
	if err := reopened.Reconcile(context.Background(), "lab", fixture(t)); err != nil {
		t.Fatal(err)
	}
	if m.mutations != mutations {
		t.Fatal("non-idempotent reconciliation")
	}
}

func TestStagedRecoveryRefusesActiveLabJournal(t *testing.T) {
	m := &mockRouter{}
	staged, client, dir := stagedControllerFixture(t, m)
	lab, err := NewLabController(client, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := fixture(t)
	want[0].Fields["disabled"] = "false"
	lab.fault = func(boundary string) error {
		if boundary == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if lab.Reconcile(context.Background(), "lab", want) == nil {
		t.Fatal("missing crash")
	}
	mutations := m.mutations
	if staged.Recover(context.Background()) == nil {
		t.Fatal("active journal accepted")
	}
	if m.mutations != mutations {
		t.Fatal("active state compensated")
	}
}

func TestControllerRejectsAmbiguousJournalAndUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"duplicate", "unknown", "lock-mode", "lock-fifo", "journal-fifo", "journal-symlink", "ancestor-symlink", "directory-mode", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			ctrl, client, dir := stagedControllerFixture(t, &mockRouter{})
			path := filepath.Join(dir, "journal.json")
			switch kind {
			case "duplicate":
				os.WriteFile(path, []byte(`{"version":1,"version":1}`), 0600)
			case "unknown":
				os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0600)
			case "lock-mode":
				os.WriteFile(filepath.Join(dir, "controller.lock"), nil, 0644)
			case "lock-fifo":
				if err := syscall.Mkfifo(filepath.Join(dir, "controller.lock"), 0600); err != nil {
					t.Fatal(err)
				}
			case "journal-fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "journal-symlink":
				os.Symlink("/dev/null", path)
			case "ancestor-symlink":
				link := filepath.Join(filepath.Dir(dir), "linked")
				os.Symlink(dir, link)
				if _, err := NewController(client, filepath.Join(link, "child")); err == nil {
					t.Fatal("symlink ancestor accepted")
				}
				return
			case "directory-mode":
				os.Chmod(dir, 0755)
			case "oversize":
				os.WriteFile(path, make([]byte, (4<<20)+1), 0600)
			}
			if ctrl.Recover(context.Background()) == nil {
				t.Fatal("unsafe journal storage accepted")
			}
		})
	}
}

func TestControllerPoisonedAfterDurabilityFailure(t *testing.T) {
	ctrl, _, dir := stagedControllerFixture(t, &mockRouter{})
	// A directory at the rename target forces a write failure after temp fsync.
	if err := os.Mkdir(filepath.Join(dir, "journal.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.persist(controllerJournal{Version: 1}); err == nil {
		t.Fatal("expected durability failure")
	}
	if err := os.Remove(filepath.Join(dir, "journal.json")); err != nil {
		t.Fatal(err)
	}
	if ctrl.Reconcile(context.Background(), "lab", fixture(t)) == nil {
		t.Fatal("poisoned writer reused")
	}
}

func TestReconcileOwnsLockAcrossDiscovery(t *testing.T) {
	ctrl, client, dir := newControllerFixture(t, &mockRouter{}, nil)
	other, err := NewLabController(client, dir)
	if err != nil {
		t.Fatal(err)
	}
	// The first mutation boundary is reached only after recovery, planning and
	// durable intent; a second controller must still be unable to enter.
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	ctrl.fault = func(boundary string) error {
		if boundary == "before-mutation" {
			close(entered)
			<-release
			return errors.New("crash")
		}
		return nil
	}
	go func() { done <- ctrl.Reconcile(context.Background(), "lab", fixture(t)) }()
	<-entered
	if err := other.Reconcile(context.Background(), "lab", fixture(t)); err == nil {
		t.Error("second reconciliation entered")
	}
	close(release)
	<-done
	if err := other.Reconcile(context.Background(), "lab", fixture(t)); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileRefusesExternalEditDuringRecovery(t *testing.T) {
	m := &mockRouter{}
	ctrl, _, _ := stagedControllerFixture(t, m)
	ctrl.fault = func(boundary string) error {
		if boundary == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Reconcile(context.Background(), "lab", fixture(t)) == nil {
		t.Fatal("missing crash")
	}
	m.objects[0].Fields["to-addresses"] = "192.0.2.99"
	ctrl.fault = nil
	mutations := m.mutations
	if ctrl.Reconcile(context.Background(), "lab", fixture(t)) == nil {
		t.Fatal("external edit accepted")
	}
	if m.mutations != mutations || m.objects[0].Fields["to-addresses"] != "192.0.2.99" {
		t.Fatal("external edit overwritten")
	}
}

func TestStagedRecoveryRejectsActiveRealizedJournal(t *testing.T) {
	m := &mockRouter{}
	ctrl, client, _ := stagedControllerFixture(t, m)
	after := Object{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab:route:canary", "disabled": "true", "dst-address": "203.0.113.125/32", "gateway": "172.30.0.2"}}
	active := controllerProjection(after)
	active.ID = "*BAD"
	active.Fields["disabled"] = "false"
	m.objects = []Object{active}
	j := controllerJournal{Version: 1, Target: client.base.String(), Instance: "lab", State: "pending", Changes: []controllerStep{{Change: Change{Action: "create", After: &after}, Attempted: true, Realized: &active}}}
	if err := ctrl.persist(j); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Recover(context.Background()); err == nil {
		t.Fatal("active realized journal accepted")
	}
	if m.mutations != 0 {
		t.Fatal("active state mutated during recovery")
	}
}
