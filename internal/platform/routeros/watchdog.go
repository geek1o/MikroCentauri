//go:build linux || darwin

package routeros

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WatchdogSpec describes a readiness probe and its exact owned steering objects.
// Readiness must include the applied generation, engine, DNS and dataplane.
// A watchdog alone does not solve persisted enabled rules at router startup: an
// independently tested boot guard or volatile dataplane lease is still required.
type WatchdogSpec struct {
	Instance         string        `json:"instance"`
	Host             string        `json:"host"`
	Port             int           `json:"port"`
	Interval         time.Duration `json:"interval"`
	Timeout          time.Duration `json:"timeout"`
	SuccessThreshold int           `json:"success_threshold"`
	Targets          []Object      `json:"targets"`
}

const watchdogSpecPrefix = "# mikrocentauri-watchdog-v1:"

// DesiredWatchdog builds a disabled native Netwatch HTTP probe. DOWN is immediate;
// UP requires consecutive successful probes and exact target configuration.
func DesiredWatchdog(spec WatchdogSpec) (Object, error) {
	if !instancePattern.MatchString(spec.Instance) {
		return Object{}, errors.New("invalid watchdog instance")
	}
	host, err := netip.ParseAddr(spec.Host)
	if err != nil || !host.Is4() || host.IsUnspecified() || host.IsMulticast() {
		return Object{}, errors.New("watchdog requires a unicast IPv4 readiness address")
	}
	if spec.Port < 1 || spec.Port > 65535 || spec.Interval < time.Second || spec.Interval > time.Minute || spec.Timeout < time.Millisecond || spec.Timeout >= spec.Interval || spec.Interval%time.Millisecond != 0 || spec.Timeout%time.Millisecond != 0 || spec.SuccessThreshold < 2 || spec.SuccessThreshold > 10 {
		return Object{}, errors.New("invalid watchdog probe or debounce bounds")
	}
	if len(spec.Targets) == 0 || len(spec.Targets) > 16 {
		return Object{}, errors.New("watchdog requires 1 to 16 steering targets")
	}
	spec.Targets = append([]Object(nil), spec.Targets...)
	sort.Slice(spec.Targets, func(i, j int) bool { return key(spec.Targets[i]) < key(spec.Targets[j]) })
	seen := map[string]bool{}
	for _, o := range spec.Targets {
		if !Owned(spec.Instance, o) || o.ID != "" || (o.Path != "ip/route" && o.Path != "ip/firewall/nat" && o.Path != "ip/firewall/mangle") || seen[key(o)] || len(o.Fields) < 3 || len(o.Fields) > 32 {
			return Object{}, errors.New("invalid exact watchdog steering target")
		}
		if o.Fields["disabled"] != "true" && o.Fields["disabled"] != "false" {
			return Object{}, errors.New("watchdog targets require explicit disabled state")
		}
		for k, v := range o.Fields {
			if !controllerWritable[o.Path][k] || len(v) > 512 || strings.ContainsAny(v, "\r\n\x00") {
				return Object{}, errors.New("unsupported watchdog target field")
			}
		}
		seen[key(o)] = true
	}
	comment := "mikrocentauri:" + spec.Instance + ":netwatch:readiness"
	counterList := "mc-" + spec.Instance + "-watch-count"
	counterComment := "mikrocentauri:" + spec.Instance + ":watchdog-counter"
	clearCounter := watchdogCounterClear(spec.Instance)
	down := clearCounter + watchdogDisable(spec.Targets)
	encoded, err := json.Marshal(spec)
	if err != nil {
		return Object{}, err
	}
	// The inert comment binds the persisted script to the exact structured input.
	// Validation regenerates the entire object rather than accepting script text.
	script := watchdogSpecPrefix + base64.RawStdEncoding.EncodeToString(encoded) + "\n"
	script += ":do { :local count 0; "
	script += ":local watch [/tool/netwatch/find where comment=" + watchdogQuote(comment) + "]; :local ready false; :if ([:len $watch] = 1) do={ :set ready ([/tool/netwatch/get $watch status] = \"up\"); "
	// An unrelated HTTP200 cannot stand in for the applied generation readiness
	// endpoint if an external actor changes the native observer tuple.
	for _, field := range []struct{ name, value string }{{"host", host.String()}, {"type", "http-get"}, {"port", strconv.Itoa(spec.Port)}, {"http-codes", "200"}} {
		script += ":if ([:tostr [/tool/netwatch/get $watch " + field.name + "]] != " + watchdogQuote(field.value) + ") do={ :set ready false; }; "
	}
	script += "}; "
	for _, o := range spec.Targets {
		path := "/" + o.Path
		script += ":local rows [" + path + "/find where comment=" + watchdogQuote(o.Fields["comment"]) + "]; :if ([:len $rows] != 1) do={ :set ready false; } else={ "
		fields := make([]string, 0, len(o.Fields))
		for k := range o.Fields {
			if k != "comment" && k != "disabled" {
				fields = append(fields, k)
			}
		}
		sort.Strings(fields)
		for _, k := range fields {
			script += ":if ([:tostr [" + path + "/get $rows " + k + "]] != " + watchdogQuote(o.Fields[k]) + ") do={ :set ready false; }; "
		}
		script += "}; "
	}

	// Netwatch globals are invocation-local on the verified RouterOS build. A
	// finite dynamic address-list row keeps debounce state in RAM across probes.
	script += ":local counters [/ip/firewall/address-list/find where list=" + watchdogQuote(counterList) + "]; :if ([:len $counters] > 1) do={ :set ready false; }; :if ([:len $counters] = 1) do={ :if (([/ip/firewall/address-list/get $counters dynamic] != true) || ([/ip/firewall/address-list/get $counters comment] != " + watchdogQuote(counterComment) + ")) do={ :set ready false; } else={ "
	for n := 1; n <= spec.SuccessThreshold; n++ {
		script += ":if ([:tostr [/ip/firewall/address-list/get $counters address]] = " + watchdogQuote("127.0.0."+strconv.Itoa(n)) + ") do={ :set count " + strconv.Itoa(n) + "; }; "
	}
	script += ":if ($count = 0) do={ :set ready false; }; }; }; "
	script += ":if ($ready = false) do={ " + clearCounter + watchdogDisable(spec.Targets) + "} else={ :if ($count < " + strconv.Itoa(spec.SuccessThreshold) + ") do={ :set count ($count + 1); }; :do { " + clearCounter + "/ip/firewall/address-list/add list=" + watchdogQuote(counterList) + " address=(\"127.0.0.\".$count) timeout=" + (2*spec.Interval + spec.Timeout).String() + " comment=" + watchdogQuote(counterComment) + "; } on-error={ :set ready false; }; :if (($ready = true) && ($count >= " + strconv.Itoa(spec.SuccessThreshold) + ")) do={ "

	enableTargets := append([]Object(nil), spec.Targets...)
	sort.SliceStable(enableTargets, func(i, j int) bool {
		return enablePriority(enableTargets[i].Path) < enablePriority(enableTargets[j].Path)
	})
	for _, o := range enableTargets {
		script += watchdogSwitch(o, "enable", true)
	}
	script += "} else={ " + watchdogDisable(spec.Targets) + "}; }; } on-error={ " + down + "};"
	if len(script) > 32<<10 {
		return Object{}, errors.New("watchdog script exceeds bounded size")
	}
	return Object{Path: "tool/netwatch", Fields: map[string]string{
		"comment": comment, "disabled": "true", "host": host.String(), "type": "http-get", "port": strconv.Itoa(spec.Port),
		"interval": spec.Interval.String(), "timeout": spec.Timeout.String(),
		"start-delay": "0ms", "startup-delay": "0s", "http-codes": "200", "ignore-initial-up": "false", "ignore-initial-down": "false",
		"up-script": "", "down-script": down, "test-script": script,
	}}, nil
}

func watchdogQuote(v string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$")
	return "\"" + r.Replace(v) + "\""
}
func watchdogDisable(targets []Object) string {
	var b strings.Builder
	for _, o := range targets {
		b.WriteString(watchdogSwitch(o, "disable", false))
	}
	return b.String()
}

// WatchdogBootGuardScript returns an exact owned disable script for a native boot
// guard. Generating it does not install or prove its ordering before LAN traffic.
func WatchdogBootGuardScript(spec WatchdogSpec) (string, error) {
	if _, err := DesiredWatchdog(spec); err != nil {
		return "", err
	}
	spec.Targets = append([]Object(nil), spec.Targets...)
	sort.Slice(spec.Targets, func(i, j int) bool { return key(spec.Targets[i]) < key(spec.Targets[j]) })
	return watchdogCounterClear(spec.Instance) + watchdogDisable(spec.Targets), nil
}

// ValidateGeneratedWatchdog admits only the exact deterministic generated hooks.
// IDs and the disabled switch are runtime properties; all other fields must match.
func ValidateGeneratedWatchdog(instance string, o Object) error {
	if !Owned(instance, o) || o.Path != "tool/netwatch" || len(o.Fields["test-script"]) > 32<<10 {
		return errors.New("invalid generated watchdog ownership")
	}
	line, _, ok := strings.Cut(o.Fields["test-script"], "\n")
	if !ok || !strings.HasPrefix(line, watchdogSpecPrefix) {
		return errors.New("watchdog script is not generated")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	if err != nil || len(raw) > 24<<10 {
		return errors.New("invalid watchdog specification")
	}
	var spec WatchdogSpec
	if err = controllerDecode(raw, &spec); err != nil || spec.Instance != instance {
		return errors.New("invalid watchdog specification")
	}
	expected, err := DesiredWatchdog(spec)
	if err != nil {
		return err
	}
	if o.Fields["disabled"] != "true" && o.Fields["disabled"] != "false" {
		return errors.New("invalid watchdog disabled state")
	}
	expected.Fields["disabled"] = o.Fields["disabled"]
	if !watchdogFieldsEqual(expected.Fields, o.Fields) {
		return fmt.Errorf("watchdog fields or scripts differ from generated specification")
	}
	return nil
}
func validateGeneratedWatchdog(o Object) error {
	parts := strings.Split(o.Fields["comment"], ":")
	if len(parts) != 4 {
		return errors.New("invalid watchdog comment")
	}
	return ValidateGeneratedWatchdog(parts[1], o)
}

// WatchdogBundle contains the independently running observer and reboot guard.
// Both objects are staged disabled until a reviewed activation transaction.
func WatchdogBundle(spec WatchdogSpec) ([]Object, error) {
	watch, err := DesiredWatchdog(spec)
	if err != nil {
		return nil, err
	}
	down, err := WatchdogBootGuardScript(spec)
	if err != nil {
		return nil, err
	}
	// Carry the same inert structured specification in the guard for exact rebuild.
	header, _, _ := strings.Cut(watch.Fields["test-script"], "\n")
	guard := Object{Path: "system/scheduler", Fields: map[string]string{
		"comment": "mikrocentauri:" + spec.Instance + ":scheduler:boot-guard",
		"name":    "mc-" + spec.Instance + "-boot-direct", "disabled": "true", "start-time": "startup",
		"interval": "0s", "policy": "read,write,test", "on-event": header + "\n" + down,
	}}
	return []Object{watch, guard}, nil
}

// ValidateGeneratedBootGuard regenerates every writable scheduler field. Runtime
// counters, next-run and REST IDs must be projected out by the caller.
func ValidateGeneratedBootGuard(instance string, o Object) error {
	if o.Path != "system/scheduler" || o.Fields["comment"] != "mikrocentauri:"+instance+":scheduler:boot-guard" || !instancePattern.MatchString(instance) || len(o.Fields["on-event"]) > 32<<10 {
		return errors.New("invalid boot guard ownership")
	}
	line, _, ok := strings.Cut(o.Fields["on-event"], "\n")
	if !ok || !strings.HasPrefix(line, watchdogSpecPrefix) {
		return errors.New("boot guard is not generated")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	if err != nil || len(raw) > 24<<10 {
		return errors.New("invalid boot guard specification")
	}
	var spec WatchdogSpec
	if err = controllerDecode(raw, &spec); err != nil || spec.Instance != instance {
		return errors.New("invalid boot guard specification")
	}
	bundle, err := WatchdogBundle(spec)
	if err != nil {
		return err
	}
	expected := bundle[1]
	if o.Fields["disabled"] != "true" && o.Fields["disabled"] != "false" {
		return errors.New("invalid boot guard disabled state")
	}
	expected.Fields["disabled"] = o.Fields["disabled"]
	if !reflect.DeepEqual(expected.Fields, o.Fields) {
		return errors.New("boot guard differs from generated specification")
	}
	return nil
}

// REST/controller projections omit an empty up hook. No other absent field or
// unrecognized empty field is admitted by this normalization.
func watchdogFieldsEqual(a, b map[string]string) bool {
	aa, bb := map[string]string{}, map[string]string{}
	for k, v := range a {
		if k == "up-script" && v == "" {
			continue
		}
		aa[k] = v
	}
	for k, v := range b {
		if k == "up-script" && v == "" {
			continue
		}
		bb[k] = v
	}
	return reflect.DeepEqual(aa, bb)
}

// Only finite dynamic rows with the exact counter identity are removed. A static
// or foreign row blocks UP admission and is preserved for operator inspection.
func watchdogCounterClear(instance string) string {
	return "/ip/firewall/address-list/remove [find where list=" + watchdogQuote("mc-"+instance+"-watch-count") + " and comment=" + watchdogQuote("mikrocentauri:"+instance+":watchdog-counter") + " and dynamic=yes]; "
}

func watchdogSwitch(o Object, action string, disabled bool) string {
	return ":foreach row in=[/" + o.Path + "/find where comment=" + watchdogQuote(o.Fields["comment"]) + "] do={ :if ([/" + o.Path + "/get $row disabled] = " + strconv.FormatBool(disabled) + ") do={ /" + o.Path + "/" + action + " $row; }; }; "
}
func enablePriority(path string) int {
	switch path {
	case "ip/route":
		return 0
	case "ip/firewall/mangle":
		return 1
	default:
		return 2
	}
}
