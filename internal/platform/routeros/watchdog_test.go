package routeros

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testWatchdogSpec() WatchdogSpec {
	return WatchdogSpec{Instance: "phase2", Host: "172.30.0.2", Port: 9099, Interval: 2 * time.Second, Timeout: time.Second, SuccessThreshold: 3, Targets: []Object{
		{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:phase2:route:canary", "disabled": "true", "dst-address": "203.0.113.124/32", "gateway": "172.30.0.2", "routing-table": "main"}},
		{Path: "ip/firewall/nat", Fields: map[string]string{"comment": "mikrocentauri:phase2:nat:dns", "disabled": "true", "chain": "dstnat", "action": "dst-nat", "protocol": "udp", "dst-port": "53", "to-addresses": "172.30.0.2", "to-ports": "5353"}},
	}}
}

func TestWatchdogExactGeneratedHooks(t *testing.T) {
	s := testWatchdogSpec()
	bundle, err := WatchdogBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateGeneratedWatchdog(s.Instance, bundle[0]); err != nil {
		t.Fatal(err)
	}
	if err = ValidateGeneratedBootGuard(s.Instance, bundle[1]); err != nil {
		t.Fatal(err)
	}
	for _, o := range bundle {
		if o.Fields["disabled"] != "true" {
			t.Fatal("not staged")
		}
	}
	script := bundle[0].Fields["test-script"]
	if strings.Contains(script, "~") || strings.Contains(script, "/system/script/run") {
		t.Fatal("broad selector or arbitrary script")
	}
	for _, target := range s.Targets {
		if !strings.Contains(script, `comment="`+target.Fields["comment"]+`"`) {
			t.Fatal("missing exact target")
		}
	}
	if !strings.Contains(script, `[:len $rows] != 1`) || !strings.Contains(script, `[:tostr [/ip/route/get $rows gateway]] != "172.30.0.2"`) || !strings.Contains(script, `>= 3`) {
		t.Fatal("missing content admission or debounce")
	}
	if !strings.Contains(bundle[0].Fields["down-script"], "address-list/remove") || strings.Contains(bundle[0].Fields["down-script"], "/enable") {
		t.Fatal("DOWN must reset and disable")
	}
	// Planner desired ordering and metadata do not depend on caller slice order.
	s.Targets[0], s.Targets[1] = s.Targets[1], s.Targets[0]
	again, err := DesiredWatchdog(s)
	if err != nil {
		t.Fatal(err)
	}
	if again.Fields["test-script"] != script {
		t.Fatal("non deterministic generation")
	}
}

func TestWatchdogRejectsScriptTampering(t *testing.T) {
	s := testWatchdogSpec()
	original, _ := WatchdogBundle(s)
	for _, field := range []string{"up-script", "down-script", "test-script", "host", "port", "http-codes", "comment"} {
		t.Run(field, func(t *testing.T) {
			o := copyWatchObject(original[0])
			o.Fields[field] += " /system/reboot"
			if ValidateGeneratedWatchdog(s.Instance, o) == nil {
				t.Fatal("accepted tampering")
			}
		})
	}
	guard := copyWatchObject(original[1])
	guard.Fields["on-event"] += " /system/reboot"
	if ValidateGeneratedBootGuard(s.Instance, guard) == nil {
		t.Fatal("accepted arbitrary scheduler hook")
	}
	for _, o := range original {
		o.Fields["disabled"] = "false"
		if o.Path == "tool/netwatch" {
			if err := ValidateGeneratedWatchdog(s.Instance, o); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := ValidateGeneratedBootGuard(s.Instance, o); err != nil {
				t.Fatal(err)
			}
		}
	}
	if ValidateGeneratedWatchdog("another", original[0]) == nil {
		t.Fatal("cross instance accepted")
	}
}
func copyWatchObject(o Object) Object {
	n := Object{Path: o.Path, ID: o.ID, Fields: map[string]string{}}
	for k, v := range o.Fields {
		n.Fields[k] = v
	}
	return n
}

func TestWatchdogTargetAdmission(t *testing.T) {
	for _, mutation := range []struct {
		name string
		edit func(*WatchdogSpec)
	}{
		{"no targets", func(s *WatchdogSpec) { s.Targets = nil }},
		{"duplicate", func(s *WatchdogSpec) { s.Targets = append(s.Targets, s.Targets[0]) }},
		{"foreign", func(s *WatchdogSpec) { s.Targets[0].Fields["comment"] = "mikrocentauri:foreign:route:canary" }},
		{"runtime id", func(s *WatchdogSpec) { s.Targets[0].ID = "*1" }},
		{"script field", func(s *WatchdogSpec) { s.Targets[0].Fields["on-event"] = "/system/reboot" }},
		{"missing disabled", func(s *WatchdogSpec) { delete(s.Targets[0].Fields, "disabled") }},
		{"control character", func(s *WatchdogSpec) { s.Targets[0].Fields["gateway"] = "172.30.0.2\n/system/reboot" }},
		{"multicast", func(s *WatchdogSpec) { s.Host = "224.0.0.1" }},
		{"injection host", func(s *WatchdogSpec) { s.Host = "172.30.0.2; /system/reboot" }},
		{"threshold one", func(s *WatchdogSpec) { s.SuccessThreshold = 1 }},
		{"timeout", func(s *WatchdogSpec) { s.Timeout = s.Interval }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			s := testWatchdogSpec()
			mutation.edit(&s)
			if _, err := DesiredWatchdog(s); err == nil {
				t.Fatal("accepted invalid spec")
			}
		})
	}
}

func TestWatchdogQuotedTargetCannotInject(t *testing.T) {
	s := testWatchdogSpec()
	s.Targets[0].Fields["gateway"] = `a"; /system/reboot; :put "$evil`
	o, err := DesiredWatchdog(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Fields["test-script"], `a\"; /system/reboot; :put \"\$evil`) {
		t.Fatal("target value not escaped")
	}
	if ValidateGeneratedWatchdog(s.Instance, o) != nil {
		t.Fatal("generated script rejected")
	}
}

func TestWatchdogMetadataMustMatchHooks(t *testing.T) {
	s := testWatchdogSpec()
	o, _ := DesiredWatchdog(s)
	s.Targets[0].Fields["gateway"] = "172.30.0.3"
	raw, _ := json.Marshal(s)
	_, body, _ := strings.Cut(o.Fields["test-script"], "\n")
	o.Fields["test-script"] = watchdogSpecPrefix + base64.RawStdEncoding.EncodeToString(raw) + "\n" + body
	if ValidateGeneratedWatchdog(s.Instance, o) == nil {
		t.Fatal("accepted changed metadata without regenerated hooks")
	}
}

func TestWatchdogProjectedHooksAndStrictMetadata(t *testing.T) {
	s := testWatchdogSpec()
	watch, _ := DesiredWatchdog(s)
	delete(watch.Fields, "up-script")
	if err := ValidateGeneratedWatchdog(s.Instance, watch); err != nil {
		t.Fatal("empty projected hook rejected", err)
	}
	watch.Fields["unknown"] = ""
	if ValidateGeneratedWatchdog(s.Instance, watch) == nil {
		t.Fatal("unknown empty field admitted")
	}
	delete(watch.Fields, "unknown")
	line, body, _ := strings.Cut(watch.Fields["test-script"], "\n")
	raw, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), append([]byte(`{"instance":"phase2",`), raw[1:]...)} {
		changed := copyWatchObject(watch)
		changed.Fields["test-script"] = watchdogSpecPrefix + base64.RawStdEncoding.EncodeToString(bad) + "\n" + body
		if ValidateGeneratedWatchdog(s.Instance, changed) == nil {
			t.Fatal("ambiguous metadata accepted")
		}
	}
}

// Native CHR 7.24.5 showed Netwatch globals are not preserved across test-script
// invocations: every successful probe stayed at count1. The debounce must use
// independently persistent, finite, RAM-only state instead of globals.
func TestWatchdogDebounceUsesFiniteNativeRAMState(t *testing.T) {
	s := testWatchdogSpec()
	bundle, err := WatchdogBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	script := bundle[0].Fields["test-script"]
	if strings.Contains(script, ":global") || strings.Contains(bundle[1].Fields["on-event"], ":global") {
		t.Fatal("invocation globals cannot implement debounce")
	}
	for _, fragment := range []string{`list="mc-phase2-watch-count"`, `comment="mikrocentauri:phase2:watchdog-counter"`, `timeout=5s`, `address=("127.0.0.".$count)`, `get $counters dynamic] != true`, `[:len $counters] > 1`, `127.0.0.1`, `127.0.0.2`, `127.0.0.3`, `($count >= 3)`} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("missing native debounce barrier %s", fragment)
		}
	}
	for _, field := range []string{"down-script"} {
		if !strings.Contains(bundle[0].Fields[field], "and dynamic=yes") {
			t.Fatal("DOWN must preserve static/foreign counter rows")
		}
	}
	if !strings.Contains(bundle[1].Fields["on-event"], "and dynamic=yes") {
		t.Fatal("boot guard must clear only exact dynamic counters")
	}
}

func TestWatchdogObserverTupleAdmission(t *testing.T) {
	s := testWatchdogSpec()
	o, err := DesiredWatchdog(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`get $watch host]] != "172.30.0.2"`, `get $watch type]] != "http-get"`, `get $watch port]] != "9099"`, `get $watch http-codes]] != "200"`} {
		if !strings.Contains(o.Fields["test-script"], fragment) {
			t.Fatalf("observer admission missing %s", fragment)
		}
	}
	if !strings.Contains(o.Fields["test-script"], `} on-error={ /ip/firewall/address-list/remove`) {
		t.Fatal("native getter faults must disable steering")
	}
}
