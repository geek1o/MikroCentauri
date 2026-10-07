//go:build linux || darwin

package routeros

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"mikrocentauri.local/core/internal/fakeip"
)

// MappingBackendOptions binds immutable aliases to one dedicated owned chain
// and a generated observer's finite LAN lease. The jump remains enabled DOWN.
// Provisioning and reviewed placement are performed by the controller; this
// backend creates only map rows and never changes the jump or observer.
type MappingBackendOptions struct {
	Instance        string
	Chain           string
	LANCIDR         string
	LANInterface    string
	FakeIPRange     string
	UpLeaseList     string
	JumpComment     string
	JumpPlaceBefore string
	Observer        Object
}

// MappingBackend shares the durable alias update implementation with lab fixtures.
type MappingBackend = LabMappingBackend

var mappingIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)

func validateMappingProfile(o MappingBackendOptions) error {
	lan, err := netip.ParsePrefix(o.LANCIDR)
	if err != nil || !lan.Addr().Is4() || lan != lan.Masked() || lan.Bits() < 8 || lan.Addr().IsUnspecified() || lan.Addr().IsMulticast() || lan.Addr().IsLoopback() {
		return errors.New("invalid mapping LAN prefix")
	}
	fake, err := netip.ParsePrefix(o.FakeIPRange)
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	if err != nil || !fake.Addr().Is4() || fake != fake.Masked() || fake.Bits() < benchmark.Bits() || fake.Bits() > 30 || !benchmark.Contains(fake.Addr()) || lan.Overlaps(fake) {
		return errors.New("invalid mapping FakeIP prefix")
	}
	if !instancePattern.MatchString(o.Instance) || !mappingIdentifier.MatchString(o.Chain) || !strings.HasPrefix(o.Chain, "mc-"+o.Instance+"-") || !mappingIdentifier.MatchString(o.LANInterface) || o.UpLeaseList != "mc-"+o.Instance+"-up-lease" || o.JumpComment != "mikrocentauri:"+o.Instance+":nat:backup-jump" {
		return errors.New("invalid mapping ownership or interface")
	}
	if o.JumpPlaceBefore != "" && !regexp.MustCompile(`^\*[0-9A-Fa-f]{1,16}$`).MatchString(o.JumpPlaceBefore) {
		return errors.New("invalid mapping placement anchor")
	}
	if err := ValidateGeneratedWatchdog(o.Instance, o.Observer); err != nil {
		return err
	}
	line, _, _ := strings.Cut(o.Observer.Fields["test-script"], "\n")
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	var spec WatchdogSpec
	if err != nil || controllerDecode(raw, &spec) != nil || spec.LANLeaseCIDR != o.LANCIDR {
		return errors.New("mapping observer must bind the exact LAN lease")
	}
	for _, target := range spec.Targets {
		if target.Fields["comment"] == o.JumpComment || target.Fields["chain"] == o.Chain {
			return errors.New("fallback rules cannot be switched by readiness")
		}
	}
	return nil
}

// DesiredMappingJump builds the permanent fallback jump. Its order must be
// reviewed before activation; the mapping writer never moves NAT rules.
func DesiredMappingJump(o MappingBackendOptions) (Object, error) {
	if err := validateMappingProfile(o); err != nil {
		return Object{}, err
	}
	return Object{Path: "ip/firewall/nat", PlaceBefore: o.JumpPlaceBefore, Fields: mappingJumpFields(o)}, nil
}
func mappingJumpFields(o MappingBackendOptions) map[string]string {
	return map[string]string{"comment": o.JumpComment, "chain": "dstnat", "action": "jump", "jump-target": o.Chain, "in-interface": o.LANInterface, "src-address": o.LANCIDR, "dst-address": o.FakeIPRange, "src-address-list": "!" + o.UpLeaseList, "disabled": "false"}
}

// NewMappingBackend requires verified HTTPS. Every publication rechecks the
// exact observer, steering targets, volatile identities and dedicated NAT chain.
func NewMappingBackend(c *Client, o MappingBackendOptions) (*MappingBackend, error) {
	if c == nil || c.base.Scheme != "https" {
		return nil, errors.New("mapping backend requires HTTPS")
	}
	if err := validateMappingProfile(o); err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(o.Observer.Fields["test-script"], "\n")
	raw, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	var spec WatchdogSpec
	if controllerDecode(raw, &spec) != nil {
		return nil, errors.New("invalid mapping observer")
	}
	barrier, err := NewCoreNativeBarrier(c, CoreNativeBarrierOptions{Instance: o.Instance, Observer: o.Observer, ReservedLists: WatchdogReservedLists(spec)})
	if err != nil {
		return nil, err
	}
	// Retain no mutable caller-owned maps.
	o.Observer = barrier.options.Observer
	return &MappingBackend{client: c, lease: true, profile: &o, barrier: barrier}, nil
}
func (b *LabMappingBackend) fields(m fakeip.Mapping) (map[string]string, error) {
	if b.profile == nil {
		return mappingFields(m)
	}
	o := b.profile
	fake, _ := netip.ParsePrefix(o.FakeIPRange)
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	if !m.Fake.Is4() || !fake.Contains(m.Fake) || !m.Real.Is4() || m.Real.IsUnspecified() || m.Real.IsMulticast() || benchmark.Contains(m.Real) {
		return nil, errors.New("invalid immutable map")
	}
	bits := m.Fake.As4()
	return map[string]string{"comment": fmt.Sprintf("mikrocentauri:%s:nat:map-%08x", o.Instance, binary.BigEndian.Uint32(bits[:])), "chain": o.Chain, "action": "dst-nat", "src-address": o.LANCIDR, "dst-address": m.Fake.String(), "to-addresses": m.Real.String(), "disabled": "false"}, nil
}

// VerifyProfile checks the provisioned fallback and independently enabled native
// watchdog/boot guard. Live finite authority is allowed; foreign authority is not.
func (b *LabMappingBackend) VerifyProfile(ctx context.Context) error {
	_, err := b.profileRows(ctx)
	return err
}
func (b *LabMappingBackend) profileRows(ctx context.Context) ([]Object, error) {
	if b.profile == nil || b.barrier == nil {
		return nil, errors.New("production mapping profile required")
	}
	paths := []string{"ip/firewall/nat", "ip/route", "tool/netwatch", "system/scheduler", "ip/firewall/address-list"}
	for _, target := range b.barrier.targets {
		if target.Path == "ip/firewall/mangle" {
			paths = append(paths, "ip/firewall/mangle")
			break
		}
	}
	rows, err := b.profileDiscover(ctx, paths)
	if err != nil {
		return nil, err
	}
	snapshot := map[string][]map[string]string{}
	for _, row := range rows {
		fields := map[string]string{".id": row.ID}
		for k, v := range row.Fields {
			fields[k] = v
		}
		snapshot[row.Path] = append(snapshot[row.Path], fields)
	}
	if _, err := b.barrier.revokedUsing(ctx, func(_ context.Context, path string) ([]map[string]string, error) { return snapshot[path], nil }); err != nil {
		return nil, err
	}
	aliases := map[string]bool{}
	for _, row := range rows {
		if row.Path != "ip/firewall/nat" {
			continue
		}
		if row.Fields["jump-target"] == b.profile.Chain && row.Fields["comment"] != b.profile.JumpComment {
			return nil, errors.New("foreign jump into reserved mapping chain")
		}
		if row.Fields["chain"] != b.profile.Chain {
			continue
		}
		alias, err := netip.ParseAddr(row.Fields["dst-address"])
		if err != nil {
			return nil, errors.New("invalid reserved chain alias")
		}
		real, err := netip.ParseAddr(row.Fields["to-addresses"])
		if err != nil {
			return nil, errors.New("invalid reserved chain target")
		}
		want, err := b.fields(fakeip.Mapping{Fake: alias, Real: real})
		if err != nil || aliases[alias.String()] || !exactNAT(row, want) {
			return nil, errors.New("conflicting reserved chain rule")
		}
		aliases[alias.String()] = true
	}
	line, _, _ := strings.Cut(b.profile.Observer.Fields["test-script"], "\n")
	raw, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
	var spec WatchdogSpec
	if controllerDecode(raw, &spec) != nil {
		return nil, errors.New("invalid runtime profile")
	}
	bundle, err := WatchdogBundle(spec)
	if err != nil {
		return nil, err
	}
	expected := []Object{{Path: "ip/firewall/nat", PlaceBefore: b.profile.JumpPlaceBefore, Fields: mappingJumpFields(*b.profile)}, bundle[0], bundle[1]}
	for _, want := range expected {
		want.Fields["disabled"] = "false"
		count := 0
		for _, row := range rows {
			if row.Path != want.Path || row.Fields["comment"] != want.Fields["comment"] {
				continue
			}
			count++
			if want.PlaceBefore != "" {
				if err := validateDesiredPlacement(rows, want); err != nil {
					return nil, err
				}
			}
			if row.Fields["dynamic"] == "true" || row.Fields["invalid"] == "true" || !controllerSame(row, want) {
				return nil, errors.New("runtime profile configuration differs")
			}
			// Unknown non-runtime fields cannot silently broaden steering.
			for field, value := range row.Fields {
				if value != "" && !controllerWritable[row.Path][field] && !controllerReadOnly(field) {
					return nil, errors.New("runtime profile has unsupported fields")
				}
			}
		}
		if count != 1 {
			return nil, errors.New("runtime profile ownership ambiguous")
		}
	}
	for _, target := range spec.Targets {
		if target.PlaceBefore == "" {
			continue
		}
		if target.Path != "ip/firewall/nat" && target.Path != "ip/firewall/mangle" {
			return nil, errors.New("unordered steering target has placement anchor")
		}
		for _, row := range rows {
			if row.Path == target.Path && row.Fields["comment"] == target.Fields["comment"] {
				if err := validateDesiredPlacement(rows, target); err != nil {
					return nil, err
				}
			}
		}
	}

	return rows, nil
}

// Four bounded concurrent collection reads form one proof snapshot. Snapshots
// are local to this invocation and are never reused by another DNS answer.
func (b *LabMappingBackend) profileDiscover(ctx context.Context, paths []string) ([]Object, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([][]Object, len(paths))
	failures := make([]error, len(paths))
	jobs := make(chan int, len(paths))
	for i := range paths {
		jobs <- i
	}
	close(jobs)
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Go(func() {
			for index := range jobs {
				if paths[index] == "ip/firewall/address-list" {
					var lists []map[string]string
					lists, failures[index] = b.barrier.rows(ctx, paths[index])
					for _, list := range lists {
						object := Object{Path: paths[index], ID: list[".id"], Fields: map[string]string{}}
						for k, v := range list {
							if k != ".id" {
								object.Fields[k] = v
							}
						}
						results[index] = append(results[index], object)
					}
				} else {
					results[index], failures[index] = b.client.discover(ctx, []string{paths[index]})
				}
				if failures[index] != nil {
					cancel()
				}
			}
		})
	}
	group.Wait()
	// A malformed/denied collection is permanent even when cancelling peer
	// reads also produces transport errors earlier in the ordered result set.
	for _, failure := range failures {
		if failure != nil && !errors.Is(failure, ErrReadUnavailable) && !errors.Is(failure, context.Canceled) {
			return nil, failure
		}
	}
	var rows []Object
	for i := range paths {
		if failures[i] != nil {
			return nil, failures[i]
		}
		rows = append(rows, results[i]...)
	}
	return rows, ctx.Err()
}
