//go:build linux || darwin

package routeros

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// CoreReservedList binds a volatile native lease/counter to its exact identity.
// Address is optional for generated watchdog counters, whose address advances.
type CoreReservedList struct{ List, Comment, Address string }
type CoreNativeBarrierOptions struct {
	Instance      string
	Observer      Object
	ReservedLists []CoreReservedList
}

// CoreNativeBarrier never enables native traffic. Quarantine waits for the
// readiness observer to consume DOWN and for its volatile authority to disappear.
// DNS/HTTP readiness must already be held by the caller before Quarantine.
type CoreNativeBarrier struct {
	client    *Client
	options   CoreNativeBarrierOptions
	targets   []Object
	threshold int
}

var errCoreNativeTransport = errors.New("native read unavailable")

func NewCoreNativeBarrier(c *Client, o CoreNativeBarrierOptions) (*CoreNativeBarrier, error) {
	if c == nil || c.base.Scheme != "https" {
		return nil, errors.New("native barrier requires HTTPS")
	}
	return newCoreNativeBarrier(c, o, false)
}

// NewLabCoreNativeBarrier permits a disposable HTTP fixture and a pinned legacy
// observer. Production requires regenerated observer hook validation instead.
func NewLabCoreNativeBarrier(c *Client, o CoreNativeBarrierOptions) (*CoreNativeBarrier, error) {
	return newCoreNativeBarrier(c, o, true)
}
func newCoreNativeBarrier(c *Client, o CoreNativeBarrierOptions, lab bool) (*CoreNativeBarrier, error) {
	if c == nil || !Owned(o.Instance, o.Observer) || o.Observer.Path != "tool/netwatch" || len(o.ReservedLists) == 0 || len(o.ReservedLists) > 2 {
		return nil, errors.New("invalid native barrier identity")
	}
	var spec WatchdogSpec
	if !lab {
		if err := ValidateGeneratedWatchdog(o.Instance, o.Observer); err != nil {
			return nil, err
		}
		line, _, _ := strings.Cut(o.Observer.Fields["test-script"], "\n")
		raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, watchdogSpecPrefix))
		if err != nil || controllerDecode(raw, &spec) != nil {
			return nil, errors.New("invalid native generated policy")
		}
		if len(o.ReservedLists) != 1 || o.ReservedLists[0].List != "mc-"+o.Instance+"-watch-count" || o.ReservedLists[0].Comment != "mikrocentauri:"+o.Instance+":watchdog-counter" || o.ReservedLists[0].Address != "" {
			return nil, errors.New("generated observer requires exact counter identity")
		}
	}
	for _, field := range []string{"host", "port", "type", "http-codes"} {
		if o.Observer.Fields[field] == "" {
			return nil, errors.New("incomplete pinned native observer")
		}
	}
	seen := map[string]bool{}
	for _, list := range o.ReservedLists {
		if !strings.HasPrefix(list.List, "mc-"+o.Instance+"-") || !strings.HasPrefix(list.Comment, "mikrocentauri:"+o.Instance+":") || seen[list.List] {
			return nil, errors.New("invalid native reserved list")
		}
		seen[list.List] = true
	}
	copy := Object{Path: o.Observer.Path, Fields: map[string]string{}}
	for k, v := range o.Observer.Fields {
		copy.Fields[k] = v
	}
	o.Observer = copy
	o.ReservedLists = append([]CoreReservedList(nil), o.ReservedLists...)
	return &CoreNativeBarrier{client: c, options: o, targets: spec.Targets, threshold: spec.SuccessThreshold}, nil
}
func (b *CoreNativeBarrier) rows(ctx context.Context, path string) ([]map[string]string, error) {
	u := *b.client.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid native read")
	}
	req.SetBasicAuth(b.client.user, b.client.password)
	resp, err := b.client.http.Do(req)
	if err != nil {
		return nil, errCoreNativeTransport
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("native read denied")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 {
		return nil, errors.New("native response exceeds bounds")
	}
	var rows []map[string]string
	if controllerDecode(raw, &rows) != nil || rows == nil {
		return nil, errors.New("invalid native response")
	}
	return rows, nil
}
func (b *CoreNativeBarrier) revoked(ctx context.Context) (bool, error) {
	rows, err := b.rows(ctx, "tool/netwatch")
	if err != nil {
		return false, err
	}
	var observer map[string]string
	for _, row := range rows {
		if row["comment"] == b.options.Observer.Fields["comment"] {
			if observer != nil {
				return false, errors.New("duplicate native observer")
			}
			observer = row
		}
	}
	if observer == nil {
		return false, errors.New("native observer absent")
	}
	for k, v := range b.options.Observer.Fields {
		if k == "disabled" {
			continue
		}
		if observer[k] != v {
			return false, errors.New("native observer configuration differs")
		}
	}
	if observer["disabled"] != "true" && observer["disabled"] != "false" {
		return false, errors.New("invalid native observer state")
	}
	down := observer["disabled"] == "true" || observer["status"] == "down"
	for _, target := range b.targets {
		targetRows, err := b.rows(ctx, target.Path)
		if err != nil {
			return false, err
		}
		count := 0
		for _, row := range targetRows {
			if row["comment"] != target.Fields["comment"] {
				continue
			}
			count++
			for field, value := range target.Fields {
				if field == "disabled" {
					continue
				}
				if row[field] != value {
					return false, errors.New("native steering target differs")
				}
			}
			if row["disabled"] != "true" {
				down = false
			}
		}
		if count != 1 {
			return false, errors.New("native steering target ownership ambiguous")
		}
	}
	rows, err = b.rows(ctx, "ip/firewall/address-list")
	if err != nil {
		return false, err
	}
	empty := true
	for _, list := range b.options.ReservedLists {
		count := 0
		for _, row := range rows {
			if row["list"] != list.List {
				continue
			}
			count++
			if count > 1 || row["dynamic"] != "true" || row["comment"] != list.Comment || row["timeout"] == "" || row["timeout"] == "none-static" || list.Address != "" && row["address"] != list.Address {
				return false, errors.New("foreign or invalid native volatile authority")
			}
			duration, err := time.ParseDuration(row["timeout"])
			if err != nil || duration < 0 || duration > 15*time.Minute {
				return false, errors.New("invalid native volatile lifetime")
			}
			if b.threshold > 0 {
				address, err := netip.ParseAddr(row["address"])
				if err != nil || !address.Is4() {
					return false, errors.New("invalid native counter address")
				}
				bytes := address.As4()
				if bytes[0] != 127 || bytes[1] != 0 || bytes[2] != 0 || bytes[3] < 1 || int(bytes[3]) > b.threshold {
					return false, errors.New("invalid native counter generation")
				}
			}
			empty = false
		}
	}
	return down && empty, ctx.Err()
}
func (b *CoreNativeBarrier) Quarantine(ctx context.Context) error {
	for {
		revoked, err := b.revoked(ctx)
		if err != nil && !errors.Is(err, errCoreNativeTransport) {
			return err
		}
		if err == nil && revoked {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func (b *CoreNativeBarrier) Verify(ctx context.Context) error {
	revoked, err := b.revoked(ctx)
	if err != nil {
		return err
	}
	if !revoked {
		return errors.New("native authority remains live")
	}
	return nil
}
