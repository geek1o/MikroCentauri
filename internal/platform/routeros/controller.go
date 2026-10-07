//go:build linux || darwin

package routeros

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// LabController persists intent before writing. NewLabController permits lab
// activation; NewController stages disabled objects; NewManagedController admits
// active managed objects with generated native hooks. A journal
// belongs to one router/instance. Recover compensates interrupted transactions.
type LabController struct {
	client      *Client
	dir         string
	stagedOnly  bool
	managedOnly bool
	poisoned    atomic.Bool
	// fault is a test-only crash boundary; production callers cannot set it.
	fault func(string) error
}

type controllerJournal struct {
	Version  int              `json:"version"`
	Target   string           `json:"target"`
	Instance string           `json:"instance"`
	State    string           `json:"state"`
	Changes  []controllerStep `json:"changes"`
}
type controllerStep struct {
	Change    Change               `json:"change"`
	Attempted bool                 `json:"attempted"`
	Realized  *Object              `json:"realized,omitempty"`
	Reverted  bool                 `json:"reverted,omitempty"`
	Placement *controllerPlacement `json:"placement,omitempty"`
}

// Fields not listed here are never persisted or written. In particular runtime
// flags cannot enter rollback payloads; executable hooks require exact generation.
var controllerWritable = map[string]map[string]bool{
	"ip/route":           fieldSet("comment disabled dst-address gateway routing-table distance scope target-scope check-gateway pref-src suppress-hw-offload"),
	"ip/firewall/nat":    fieldSet("comment disabled chain action jump-target in-interface out-interface in-interface-list out-interface-list src-address dst-address src-address-list dst-address-list protocol src-port dst-port to-addresses to-ports connection-mark connection-state ipsec-policy log log-prefix"),
	"ip/firewall/mangle": fieldSet("comment disabled chain action in-interface out-interface in-interface-list out-interface-list src-address dst-address src-address-list dst-address-list protocol src-port dst-port connection-mark connection-state new-connection-mark new-routing-mark passthrough log log-prefix"),
	"ip/firewall/filter": fieldSet("comment disabled chain action in-interface out-interface in-interface-list out-interface-list src-address dst-address src-address-list dst-address-list protocol src-port dst-port connection-mark connection-state connection-nat-state ipsec-policy log log-prefix hw-offload"),
	"tool/netwatch":      fieldSet("comment disabled host type port interval timeout start-delay startup-delay http-codes thr-http-time ignore-initial-up ignore-initial-down up-script down-script test-script"),
	"system/scheduler":   fieldSet("comment name disabled start-time start-date interval policy on-event"),
}

func fieldSet(s string) map[string]bool {
	m := map[string]bool{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			m[s[start:i]] = true
			start = i + 1
		}
	}
	return m
}
func controllerProjection(o Object) Object {
	p := Object{Path: o.Path, ID: o.ID, PlaceBefore: o.PlaceBefore, Fields: map[string]string{"disabled": "false"}}
	for k, v := range o.Fields {
		if controllerWritable[o.Path][k] && v != "" {
			p.Fields[k] = v
		}
	}
	return p
}
func controllerSame(a, b Object) bool {
	a = controllerProjection(a)
	b = controllerProjection(b)
	a.ID = ""
	b.ID = ""
	a.PlaceBefore = ""
	b.PlaceBefore = ""
	return reflect.DeepEqual(a, b)
}

// Controller provisions disabled owned objects through authenticated TLS. It does
// not activate routing; activation requires separate dataplane safety barriers.
type Controller = LabController

func NewController(c *Client, directory string) (*Controller, error) {
	if c == nil || c.base.Scheme != "https" {
		return nil, errors.New("controller requires HTTPS RouterOS transport")
	}
	controller, err := NewLabController(c, directory)
	if err != nil {
		return nil, err
	}
	controller.stagedOnly = true
	return controller, nil
}

func controllerDirectory(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return errors.New("invalid journal directory")
	}
	for path := absolute; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("cannot inspect journal directory")
		}
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("journal directory ancestors must not be symlinks")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	return nil
}

func NewLabController(c *Client, directory string) (*LabController, error) {
	if c == nil || directory == "" {
		return nil, errors.New("controller requires client and private journal directory")
	}
	if e := controllerDirectory(directory); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, errors.New("cannot create journal directory")
	}
	s, e := os.Lstat(directory)
	if e != nil || !s.IsDir() || s.Mode().Perm()&0077 != 0 {
		return nil, errors.New("journal directory must be private and not a symlink")
	}
	return &LabController{client: c, dir: directory}, nil
}
func (c *LabController) lock() (func(), error) {
	if c.poisoned.Load() {
		return nil, errors.New("controller journal durability unresolved; reopen required")
	}
	if e := controllerDirectory(c.dir); e != nil {
		return nil, e
	}
	if info, err := os.Lstat(c.dir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("journal directory must remain private")
	}
	f, e := os.OpenFile(filepath.Join(c.dir, "controller.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, errors.New("cannot open controller lock")
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("controller lock must be private and regular")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("controller transaction already active")
	}
	if c.poisoned.Load() {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, errors.New("controller journal durability unresolved; reopen required")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func (c *LabController) persist(j controllerJournal) error {
	b, e := json.MarshalIndent(j, "", "  ")
	if e != nil {
		return errors.New("cannot encode controller journal")
	}
	if len(b) > 4<<20 {
		return errors.New("controller journal exceeds limit")
	}
	f, e := os.CreateTemp(c.dir, ".journal-")
	if e != nil {
		return errors.New("cannot create journal candidate")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(name, filepath.Join(c.dir, "journal.json"))
	}
	if e == nil {
		var d *os.File
		d, e = os.Open(c.dir)
		if e == nil {
			e = d.Sync()
			d.Close()
		}
	}
	if e != nil {
		c.poisoned.Store(true)
		return errors.New("cannot durably write controller journal")
	}
	return nil
}
func (c *LabController) read() (*controllerJournal, error) {
	path := filepath.Join(c.dir, "journal.json")
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || s.Size() > 4<<20 {
		return nil, errors.New("invalid private controller journal")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("cannot read controller journal")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return nil, errors.New("invalid private controller journal")
	}
	b, e := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if e != nil || len(b) > 4<<20 {
		return nil, errors.New("cannot read controller journal")
	}
	var j controllerJournal
	if controllerDecode(b, &j) != nil || j.Version != 1 || j.Target != c.client.base.String() || !instancePattern.MatchString(j.Instance) || (j.State != "pending" && j.State != "committed" && j.State != "rolled-back") {
		return nil, errors.New("invalid controller journal identity or state")
	}
	for _, s := range j.Changes {
		if e = controllerValidatePlacement(s); e != nil {
			return nil, e
		}
		if e = c.validateChange(j.Instance, s.Change); e != nil {
			return nil, errors.New("invalid journal change")
		}
		if s.Realized != nil && (!Owned(j.Instance, *s.Realized) || key(*s.Realized) != changeKey(s.Change)) {
			return nil, errors.New("invalid realized ownership")
		}
		if s.Realized != nil {
			if c.managedOnly {
				if e := managedValidateObject(j.Instance, *s.Realized); e != nil {
					return nil, e
				}
			}
			if s.Realized.ID == "" || (c.stagedOnly && s.Realized.Fields["disabled"] != "true") {
				return nil, errors.New("invalid realized staged state")
			}
			for field := range s.Realized.Fields {
				if !controllerWritable[s.Realized.Path][field] {
					return nil, errors.New("invalid realized writable field")
				}
			}
		}
	}
	return &j, nil
}

// Reject duplicate keys as well as unknown fields: journal ambiguity cannot be
// resolved safely by silently accepting the last JSON value.
func controllerDecode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("journal nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate journal key")
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid journal JSON")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing journal JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func (c *LabController) validateChange(instance string, ch Change) error {
	if c.managedOnly {
		if e := managedValidateChange(instance, ch); e != nil {
			return e
		}
	}
	for _, object := range []*Object{ch.Before, ch.After} {
		if object == nil {
			continue
		}
		if object.Path == "system/scheduler" {
			if err := ValidateGeneratedBootGuard(instance, *object); err != nil {
				return err
			}
		}
		if object.Path == "tool/netwatch" && (object.Fields["up-script"] != "" || object.Fields["down-script"] != "" || object.Fields["test-script"] != "") {
			if err := ValidateGeneratedWatchdog(instance, *object); err != nil {
				return err
			}
		}
	}
	if err := controllerValidateChange(instance, ch); err != nil {
		return err
	}
	if c.stagedOnly {
		for _, object := range []*Object{ch.Before, ch.After} {
			if object != nil && object.Fields["disabled"] != "true" {
				return errors.New("controller permits only explicitly disabled owned objects")
			}
		}
	}
	return nil
}

func controllerValidateChange(instance string, ch Change) error {
	switch ch.Action {
	case "create":
		if ch.Before != nil || ch.After == nil {
			return errors.New("invalid create")
		}
	case "update":
		if ch.Before == nil || ch.After == nil {
			return errors.New("invalid update")
		}
	case "delete":
		if ch.Before == nil || ch.After != nil {
			return errors.New("invalid delete")
		}
	default:
		return errors.New("invalid action")
	}
	for _, o := range []*Object{ch.Before, ch.After} {
		if o == nil {
			continue
		}
		if !Owned(instance, *o) {
			return errors.New("unsafe change ownership")
		}
		for f := range o.Fields {
			if !controllerWritable[o.Path][f] {
				return errors.New("unsupported writable field")
			}
		}
	}
	if ch.After != nil && ch.After.PlaceBefore != "" {
		if !controllerOrdered(ch.After.Path) || !strings.HasPrefix(ch.After.PlaceBefore, "*") || strings.ContainsAny(ch.After.PlaceBefore, "/?#\\") {
			return errors.New("invalid placement anchor")
		}
	}
	if ch.After != nil && ch.After.ID != "" {
		return errors.New("desired object contains ID")
	}
	if ch.Before != nil && ch.Before.ID == "" {
		return errors.New("current object lacks ID")
	}
	if ch.Before != nil && ch.After != nil && key(*ch.Before) != key(*ch.After) {
		return errors.New("cannot transfer ownership")
	}
	return nil
}
func controllerFind(rows []Object, k string) (*Object, error) {
	var found *Object
	for _, o := range rows {
		if key(o) == k {
			if found != nil {
				return nil, errors.New("duplicate owned object")
			}
			copy := controllerProjection(o)
			found = &copy
		}
	}
	return found, nil
}

// Apply verifies fresh snapshots, persists each mutation's intent, rediscovers
// even when an HTTP response is lost, and verifies the final writable state.
// Failure keeps a pending journal for explicit Recover; it never hides ambiguity.
func (c *LabController) Apply(ctx context.Context, p ChangePlan) error {
	if c.managedOnly {
		return c.ApplyTransactional(ctx, p)
	}
	unlock, e := c.lock()
	if e != nil {
		return e
	}
	defer unlock()
	return c.applyLocked(ctx, p)
}
func (c *LabController) applyLocked(ctx context.Context, p ChangePlan) error {
	old, e := c.read()
	if e != nil {
		return e
	}
	if old != nil && old.Instance != p.Instance {
		return errors.New("journal belongs to another instance")
	}
	if old != nil && old.State == "pending" {
		return errors.New("pending transaction requires recovery")
	}
	rows, e := c.client.Discover(ctx)
	if e != nil {
		return e
	}
	if repeat, err := c.repeated(rows, old, p); repeat {
		return err
	}
	j := controllerJournal{Version: 1, Target: c.client.base.String(), Instance: p.Instance, State: "pending"}
	seen := map[string]bool{}
	if !instancePattern.MatchString(p.Instance) {
		return errors.New("invalid instance")
	}
	for _, raw := range p.Changes {
		ch := raw
		if ch.Before != nil {
			o := controllerProjection(*ch.Before)
			ch.Before = &o
		}
		if e = c.validateChange(p.Instance, ch); e != nil {
			return e
		}
		if ch.After != nil && ch.After.PlaceBefore != "" {
			if e = validateDesiredPlacement(rows, *ch.After); e != nil {
				return e
			}
		}
		k := changeKey(ch)
		if seen[k] {
			return errors.New("duplicate plan change")
		}
		seen[k] = true
		actual, e := controllerFind(rows, k)
		if e != nil {
			return e
		}
		if ch.Before == nil {
			if actual != nil {
				return errors.New("create conflicts with existing object")
			}
		} else if actual == nil || actual.ID != ch.Before.ID || !controllerSame(*actual, *ch.Before) {
			return errors.New("stale plan requires rediscovery")
		}
		// Scripted Netwatch and unsupported configurable fields cannot be restored
		// completely. Refuse their deletion rather than silently losing user state.
		if ch.Action == "delete" {
			for _, o := range rows {
				if key(o) == k {
					for f, v := range o.Fields {
						if !controllerWritable[o.Path][f] && !controllerReadOnly(f) && v != "" {
							return errors.New("delete contains unsupported configurable state")
						}
					}
				}
			}
		}
		j.Changes = append(j.Changes, controllerStep{Change: ch})
	}
	if e = c.persist(j); e != nil {
		return e
	}
	for i := range j.Changes {
		s := &j.Changes[i]
		freshRows, freshErr := c.client.Discover(ctx)
		if freshErr != nil {
			return freshErr
		}
		fresh, freshErr := controllerFind(freshRows, changeKey(s.Change))
		if freshErr != nil {
			return freshErr
		}
		if s.Change.Before == nil && fresh != nil || s.Change.Before != nil && (fresh == nil || fresh.ID != s.Change.Before.ID || !controllerSame(*fresh, *s.Change.Before)) {
			return errors.New("concurrent edit before mutation; recovery required")
		}
		if s.Change.Action == "delete" && controllerOrdered(s.Change.Before.Path) {
			s.Placement, e = controllerSnapshotPlacement(freshRows, *s.Change.Before)
			if e != nil {
				return e
			}
		}
		s.Attempted = true
		if e = c.persist(j); e != nil {
			return e
		}
		if c.fault != nil {
			if e = c.fault("before-mutation"); e != nil {
				return e
			}
		}
		ch := s.Change
		var mutationErr error
		switch ch.Action {
		case "create":
			_, mutationErr = c.client.request(ctx, "PUT", ch.After.Path, "", controllerCreateFields(*ch.After))
		case "update":
			_, mutationErr = c.client.request(ctx, "PATCH", ch.Before.Path, ch.Before.ID, ch.After.Fields)
		case "delete":
			_, mutationErr = c.client.request(ctx, "DELETE", ch.Before.Path, ch.Before.ID, nil)
		}
		if c.fault != nil {
			if e = c.fault("after-mutation"); e != nil {
				return e
			}
		}
		rows, e = c.client.Discover(ctx)
		if e != nil {
			return errors.New("mutation outcome unresolved; recovery required")
		}
		actual, e := controllerFind(rows, changeKey(ch))
		if e != nil {
			return e
		}
		if ch.After != nil && ch.After.PlaceBefore != "" {
			if e = verifyObjectPlacement(rows, *ch.After, actual); e != nil {
				return e
			}
		}
		if !controllerExpected(ch, actual) {
			if mutationErr != nil {
				return fmt.Errorf("mutation not verified; recovery required: %w", mutationErr)
			}
			return errors.New("RouterOS writable state differs from requested state; recovery required")
		}
		s.Realized = actual
		if e = c.persist(j); e != nil {
			return e
		}
	}
	rows, e = c.client.Discover(ctx)
	if e != nil {
		return e
	}
	for _, s := range j.Changes {
		a, e := controllerFind(rows, changeKey(s.Change))
		if e != nil {
			return e
		}
		if s.Change.After != nil && s.Change.After.PlaceBefore != "" {
			if e = verifyObjectPlacement(rows, *s.Change.After, a); e != nil {
				return e
			}
		}
		if s.Change.Action == "delete" {
			if a != nil {
				return errors.New("final deletion verification failed")
			}
		} else if a == nil || s.Realized == nil || a.ID != s.Realized.ID || !controllerSame(*a, *s.Realized) {
			return errors.New("final writable state changed")
		}
	}
	j.State = "committed"
	return c.persist(j)
}
func controllerReadOnly(f string) bool {
	return fieldSet("dynamic static active invalid inactive immediate-gw belongs-to gateway-status debug fib hw-offloaded owner run-count next-run bytes packets http-resp-time http-status-code tcp-connect-time dns-resp-time last-up last-down status since done-tests failed-tests rtt-avg rtt-min rtt-max rtt-jitter packet-loss-percent sent received")[f]
}
func controllerExpected(ch Change, actual *Object) bool {
	if ch.Action == "delete" {
		return actual == nil
	}
	if actual == nil {
		return false
	}
	if ch.Action == "create" {
		return EqualManaged(*actual, *ch.After)
	}
	expected := controllerProjection(*ch.Before)
	for k, v := range ch.After.Fields {
		expected.Fields[k] = v
	}
	return actual.ID == ch.Before.ID && controllerSame(*actual, expected)
}

// Recover rolls back only values still matching our last intended/verified
// writes. Conflicting external edits stop recovery and remain untouched.
func (c *LabController) Recover(ctx context.Context) error {
	unlock, e := c.lock()
	if e != nil {
		return e
	}
	defer unlock()
	return c.recoverLocked(ctx)
}
func (c *LabController) recoverLocked(ctx context.Context) error {
	j, e := c.read()
	if e != nil || j == nil {
		return e
	}
	if j.State != "pending" {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for i := len(j.Changes) - 1; i >= 0; i-- {
		s := &j.Changes[i]
		if !s.Attempted || s.Reverted {
			continue
		}
		rows, e := c.client.Discover(rctx)
		if e != nil {
			return e
		}
		a, e := controllerFind(rows, changeKey(s.Change))
		if e != nil {
			return e
		}
		ch := s.Change
		beforeMatches := ch.Before == nil && a == nil || ch.Before != nil && a != nil && controllerSame(*a, *ch.Before)
		if beforeMatches {
			if s.Placement != nil {
				if _, e = controllerCheckPlacement(rows, *j, *s, true); e != nil {
					return e
				}
			}
			s.Reverted = true
			if e = c.persist(*j); e != nil {
				return e
			}
			continue
		}
		if s.Realized != nil {
			if a == nil || a.ID != s.Realized.ID || !controllerSame(*a, *s.Realized) {
				return errors.New("recovery refused conflicting external edit")
			}
		} else if !controllerExpected(ch, a) {
			return errors.New("recovery refused unresolved conflicting state")
		}
		switch ch.Action {
		case "create":
			_, e = c.client.request(rctx, "DELETE", a.Path, a.ID, nil)
		case "delete":
			fields := ch.Before.Fields
			if s.Placement != nil {
				anchor, err := controllerCheckPlacement(rows, *j, *s, false)
				if err != nil {
					return err
				}
				fields = map[string]string{}
				for k, v := range ch.Before.Fields {
					fields[k] = v
				}
				if anchor != "" {
					fields["place-before"] = anchor
				}
			}
			_, e = c.client.request(rctx, "PUT", ch.Before.Path, "", fields)
		case "update":
			undo := map[string]string{}
			for k := range ch.After.Fields {
				undo[k] = ch.Before.Fields[k]
			}
			_, e = c.client.request(rctx, "PATCH", a.Path, a.ID, undo)
		}
		// A lost undo response is also reconciled by ownership, never by saved IDs.
		rows, readErr := c.client.Discover(rctx)
		if readErr != nil {
			return errors.New("rollback outcome unresolved")
		}
		a, readErr = controllerFind(rows, changeKey(ch))
		if readErr != nil {
			return readErr
		}
		restored := ch.Before == nil && a == nil || ch.Before != nil && a != nil && controllerSame(*a, *ch.Before)
		if !restored {
			if e != nil {
				return errors.New("rollback failed; journal retained")
			}
			return errors.New("rollback writable verification failed")
		}
		if s.Placement != nil {
			if _, e = controllerCheckPlacement(rows, *j, *s, true); e != nil {
				return e
			}
		}
		s.Reverted = true
		if e = c.persist(*j); e != nil {
			return e
		}
	}
	j.State = "rolled-back"
	return c.persist(*j)
}

// Reconcile recovers interrupted writes before creating a fresh plan. All steps
// share one lock, so a competing controller cannot enter between recovery and
// discovery. RouterOS edits by other clients are still verified before each write.
func (c *LabController) Reconcile(ctx context.Context, instance string, desired []Object) error {
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()
	journal, err := c.read()
	if err != nil {
		return err
	}
	if journal != nil && journal.Instance != instance {
		return errors.New("journal belongs to another instance")
	}
	// Validate caller input before recovery can mutate an interrupted transaction.
	if _, err := Plan(instance, nil, desired); err != nil {
		return err
	}
	if !instancePattern.MatchString(instance) {
		return errors.New("invalid instance")
	}
	for _, object := range desired {
		if err := c.validateChange(instance, Change{Action: "create", After: &object}); err != nil {
			return err
		}
	}
	if err := c.recoverLocked(ctx); err != nil {
		return err
	}
	rows, err := c.client.Discover(ctx)
	if err != nil {
		return err
	}
	plan, err := Plan(instance, rows, desired)
	if err != nil {
		return err
	}
	err = c.applyLocked(ctx, plan)
	if err != nil && c.managedOnly {
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if recoveryErr := c.recoverLocked(recovery); recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}
	}
	return err
}
