package routeros

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"mikrocentauri.local/core/internal/fakeip"
)

const LabMappingChain = "mc-dynamic-backup"
const LabMappingJump = "mikrocentauri:lab:nat:dynamic-jump"

// LabMappingBackend creates maps with immutable aliases in a dedicated chain. The native
// watchdog changes one jump, never individual map flags; publication cannot race
// its iteration of a growing map set. Production schemas/placement remain gates.
type LabMappingBackend struct {
	client *Client
	mu     sync.Mutex
}

func NewLabMappingBackend(c *Client) (*LabMappingBackend, error) {
	if c == nil {
		return nil, errors.New("mapping client required")
	}
	return &LabMappingBackend{client: c}, nil
}
func mappingFields(m fakeip.Mapping) (map[string]string, error) {
	if !m.Fake.Is4() || !netip.MustParsePrefix("198.18.0.0/15").Contains(m.Fake) || !m.Real.Is4() || m.Real.IsUnspecified() || m.Real.IsMulticast() || netip.MustParsePrefix("198.18.0.0/15").Contains(m.Real) {
		return nil, errors.New("invalid lab map")
	}
	b := m.Fake.As4()
	return map[string]string{"comment": fmt.Sprintf("mikrocentauri:dynlab:nat:map-%08x", binary.BigEndian.Uint32(b[:])), "chain": LabMappingChain, "action": "dst-nat", "src-address": "192.168.88.0/24", "dst-address": m.Fake.String(), "to-addresses": m.Real.String(), "disabled": "false"}, nil
}
func exactNAT(o Object, want map[string]string) bool {
	for k, v := range want {
		actual := o.Fields[k]
		if k == "disabled" && actual == "" {
			actual = "false"
		}
		if actual != v {
			return false
		}
	}
	for k, v := range o.Fields {
		if k == "bytes" || k == "packets" || k == "dynamic" || k == "invalid" {
			continue
		}
		if _, ok := want[k]; !ok && v != "" {
			return false
		}
	}
	return o.Fields["dynamic"] != "true" && o.Fields["invalid"] != "true"
}

// Report only schema keys, never discovered values.
func natMismatchField(o Object, want map[string]string) string {
	keys := make([]string, 0, len(want)+len(o.Fields))
	for k := range want {
		keys = append(keys, k)
	}
	for k := range o.Fields {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v, expected := o.Fields[k], want[k]
		if k == "disabled" && v == "" {
			v = "false"
		}
		if _, ok := want[k]; ok {
			if v != expected {
				return k
			}
		} else if k != "bytes" && k != "packets" && k != "dynamic" && k != "invalid" && v != "" {
			return "unexpected_field"
		}
	}
	if o.Fields["dynamic"] == "true" {
		return "dynamic"
	}
	if o.Fields["invalid"] == "true" {
		return "invalid"
	}
	return "address_shape"
}

func (b *LabMappingBackend) inspect(ctx context.Context, m fakeip.Mapping) (*Object, error) {
	return b.inspectTransition(ctx, m, nil)
}

// Only the two journaled endpoints are allowed during recovery. REST provides
// no atomic compare-and-swap: the isolated lab requires one map writer.
func (b *LabMappingBackend) inspectTransition(ctx context.Context, m fakeip.Mapping, before *fakeip.Mapping) (*Object, error) {
	want, err := mappingFields(m)
	if err != nil {
		return nil, err
	}
	var previous map[string]string
	if before != nil {
		previous, err = mappingFields(*before)
		if err != nil {
			return nil, err
		}
	}
	rows, err := b.client.discover(ctx, []string{"ip/firewall/nat"})
	if err != nil {
		return nil, err
	}
	jumpCount := 0
	var found *Object
	jump := map[string]string{"comment": LabMappingJump, "chain": "dstnat", "action": "jump", "jump-target": LabMappingChain, "in-interface": "bridge-lan", "src-address": "192.168.88.0/24", "dst-address": "198.18.0.0/15"}
	for _, o := range rows {
		if o.Path != "ip/firewall/nat" {
			continue
		}
		if o.Fields["chain"] == LabMappingChain {
			other := fakeip.Mapping{Fake: netip.Addr{}, Real: netip.Addr{}}
			other.Fake, err = netip.ParseAddr(o.Fields["dst-address"])
			if err != nil {
				return nil, errors.New("noncanonical rule in lab mapping chain")
			}
			other.Real, err = netip.ParseAddr(o.Fields["to-addresses"])
			if err != nil {
				return nil, errors.New("noncanonical target in lab mapping chain")
			}
			shape, shapeErr := mappingFields(other)
			if shapeErr != nil || !exactNAT(o, shape) {
				return nil, fmt.Errorf("unsafe rule in lab mapping chain: %s", natMismatchField(o, shape))
			}
		}
		if o.Fields["comment"] == LabMappingJump {
			jp := o
			jp.Fields = map[string]string{}
			for k, v := range o.Fields {
				if k != "disabled" {
					jp.Fields[k] = v
				}
			}
			if !exactNAT(jp, jump) {
				return nil, errors.New("invalid lab map jump")
			}
			jumpCount++
		}
		if o.Fields["comment"] == want["comment"] || (o.Fields["chain"] == LabMappingChain && o.Fields["dst-address"] == m.Fake.String()) {
			if found != nil || (!exactNAT(o, want) && (previous == nil || !exactNAT(o, previous))) {
				return nil, errors.New("conflicting lab alias mapping")
			}
			copy := o
			found = &copy
		}
	}
	if jumpCount != 1 {
		return nil, errors.New("unique lab mapping jump required")
	}
	return found, nil
}

// Update requires a durably journaled before/after pair from the publisher.
// It changes only the real target; it never removes a rule, moves placement,
// transfers an alias, or flushes connection tracking. Recovery accepts an
// already-realized after image, including after a lost PATCH response.
func (b *LabMappingBackend) Update(ctx context.Context, before, after fakeip.Mapping) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	domain, err := fakeip.CanonicalDomain(before.Domain)
	if err != nil || domain != before.Domain || before.Domain != after.Domain || before.Fake != after.Fake {
		return errors.New("target update cannot transfer a domain or alias")
	}
	found, err := b.inspectTransition(ctx, after, &before)
	if err != nil {
		return err
	}
	if found == nil {
		return errors.New("target update requires existing map")
	}
	if found.Fields["to-addresses"] == after.Real.String() {
		return nil
	}
	if found.ID == "" {
		return errors.New("target update requires a router object ID")
	}
	_, writeErr := b.client.request(ctx, "PATCH", "ip/firewall/nat", found.ID, map[string]string{"to-addresses": after.Real.String()})
	found, err = b.inspect(ctx, after)
	if err != nil {
		return err
	}
	if found == nil {
		if writeErr != nil {
			return writeErr
		}
		return errors.New("target update not realized")
	}
	return nil
}
func (b *LabMappingBackend) Ensure(ctx context.Context, m fakeip.Mapping) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	found, err := b.inspect(ctx, m)
	if err != nil {
		return err
	}
	if found != nil {
		return nil
	}
	f, err := mappingFields(m)
	if err != nil {
		return err
	}
	// A lost PUT reply is reconciled. The publisher already durably reserved this
	// alias; ambiguity never permits a DNS answer until fresh readback succeeds.
	_, writeErr := b.client.request(ctx, "PUT", "ip/firewall/nat", "", f)
	found, err = b.inspect(ctx, m)
	if err != nil {
		return err
	}
	if found == nil {
		if writeErr != nil {
			return writeErr
		}
		return errors.New("router mapping not realized")
	}
	return nil
}
func (b *LabMappingBackend) Verify(ctx context.Context, m fakeip.Mapping) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	found, err := b.inspect(ctx, m)
	if err != nil {
		return err
	}
	if found == nil {
		return errors.New("router mapping absent")
	}
	return nil
}
