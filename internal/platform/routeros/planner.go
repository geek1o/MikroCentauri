package routeros

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"mikrocentauri.local/core/internal/config"
)

type Object struct {
	Path   string            `json:"path"`
	ID     string            `json:"id,omitempty"`
	Fields map[string]string `json:"fields"`
}
type Change struct {
	Action string  `json:"action"`
	Before *Object `json:"before,omitempty"`
	After  *Object `json:"after,omitempty"`
}
type ChangePlan struct {
	Instance string   `json:"instance"`
	Gate     string   `json:"gate"`
	Changes  []Change `json:"changes"`
}

var instancePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
var suffixPattern = regexp.MustCompile(`^(route|nat|mangle|filter|netwatch):[a-z][a-z0-9-]{0,31}$`)
var paths = map[string]bool{"ip/route": true, "ip/firewall/nat": true, "ip/firewall/mangle": true, "ip/firewall/filter": true, "tool/netwatch": true}

func Owned(instance string, o Object) bool {
	p := "mikrocentauri:" + instance + ":"
	comment := o.Fields["comment"]
	return instancePattern.MatchString(instance) && paths[o.Path] && strings.HasPrefix(comment, p) && suffixPattern.MatchString(strings.TrimPrefix(comment, p)) && strings.HasPrefix(strings.TrimPrefix(comment, p), kind(o.Path)+":")
}
func kind(path string) string {
	switch path {
	case "ip/route":
		return "route"
	case "tool/netwatch":
		return "netwatch"
	default:
		return strings.TrimPrefix(path, "ip/firewall/")
	}
}
func key(o Object) string { return o.Path + "|" + o.Fields["comment"] }
func Plan(instance string, current, desired []Object) (ChangePlan, error) {
	p := ChangePlan{Instance: instance, Gate: "NOT RUN: production activation requires dynamic FakeIP fail-open, capability/placement and controller/watchdog integration", Changes: []Change{}}
	if !instancePattern.MatchString(instance) {
		return p, errors.New("invalid ownership instance")
	}
	before := map[string]Object{}
	want := map[string]Object{}
	for _, o := range current {
		if Owned(instance, o) {
			if _, ok := before[key(o)]; ok {
				return p, errors.New("duplicate owned object")
			}
			if o.ID == "" {
				return p, errors.New("current owned object missing REST ID")
			}
			before[key(o)] = o
		}
	}
	for _, o := range desired {
		if !Owned(instance, o) {
			return p, errors.New("desired object lacks exact ownership")
		}
		if o.ID != "" {
			return p, errors.New("desired object must not prescribe REST ID")
		}
		if _, ok := want[key(o)]; ok {
			return p, errors.New("duplicate desired object")
		}
		want[key(o)] = o
	}
	for k, w := range want {
		b, ok := before[k]
		if !ok {
			a := w
			p.Changes = append(p.Changes, Change{Action: "create", After: &a})
			continue
		}
		equal := true
		for f, v := range w.Fields {
			if b.Fields[f] != v {
				equal = false
			}
		}
		if !equal {
			a, old := w, b
			p.Changes = append(p.Changes, Change{Action: "update", Before: &old, After: &a})
		}
	}
	for k, b := range before {
		if _, ok := want[k]; !ok {
			old := b
			p.Changes = append(p.Changes, Change{Action: "delete", Before: &old})
		}
	}
	sort.Slice(p.Changes, func(i, j int) bool { a, b := p.Changes[i], p.Changes[j]; return changeKey(a) < changeKey(b) })
	return p, nil
}
func changeKey(c Change) string {
	if c.After != nil {
		return key(*c.After)
	}
	return key(*c.Before)
}

// Desired is a disabled HYBRID spike preview, never a production activation plan.
// No user firewall/DNS/FastTrack object is modified and rule placement remains a lab gate.
func Desired(c config.Config) ([]Object, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Mode != "hybrid" {
		return nil, errors.New("RouterOS plan prototype currently supports hybrid only")
	}
	own := func(path, id string, fields map[string]string) Object {
		fields["comment"] = fmt.Sprintf("mikrocentauri:%s:%s:%s", c.Instance, kind(path), id)
		fields["disabled"] = "true"
		return Object{Path: path, Fields: fields}
	}
	result := []Object{own("ip/route", "fakeip", map[string]string{"dst-address": c.FakeIPRange, "gateway": c.GatewayIP, "routing-table": "main"})}
	for _, protocol := range []string{"tcp", "udp"} {
		result = append(result, own("ip/firewall/nat", "dns-"+protocol, map[string]string{"chain": "dstnat", "in-interface": c.LANInterface, "dst-address": c.LANRouterIP, "protocol": protocol, "dst-port": "53", "action": "dst-nat", "to-addresses": c.GatewayIP, "to-ports": "5353"}))
	}
	return result, nil
}

// EqualManaged compares only desired fields; REST adds runtime values and stringifies numbers.
func EqualManaged(a, b Object) bool {
	for k, v := range b.Fields {
		if a.Fields[k] != v {
			return false
		}
	}
	return a.Path == b.Path
}
