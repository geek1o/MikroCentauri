//go:build linux || darwin

package routeros

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// Store digests rather than user firewall fields. The ordered snapshot is captured
// immediately before deletion and persisted with intent, including every anchor.
type controllerPlacement struct {
	Rows  []controllerPosition `json:"rows"`
	Index int                  `json:"index"`
}
type controllerPosition struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Digest string `json:"digest"`
}

func controllerOrdered(path string) bool {
	return strings.HasPrefix(path, "ip/firewall/") && paths[path]
}
func controllerPositionOf(o Object) controllerPosition {
	fields := map[string]string{"disabled": "false"}
	for k, v := range o.Fields {
		if !controllerReadOnly(k) && v != "" {
			fields[k] = v
		}
	}
	b, _ := json.Marshal(fields)
	digest := sha256.Sum256(b)
	return controllerPosition{ID: o.ID, Key: key(o), Digest: hex.EncodeToString(digest[:])}
}
func controllerSnapshotPlacement(rows []Object, target Object) (*controllerPlacement, error) {
	p := &controllerPlacement{Index: -1}
	ids := map[string]bool{}
	for _, o := range rows {
		if o.Path != target.Path {
			continue
		}
		if o.ID == "" || ids[o.ID] || len(p.Rows) >= 4096 {
			return nil, errors.New("invalid ordered firewall snapshot")
		}
		ids[o.ID] = true
		if o.ID == target.ID {
			p.Index = len(p.Rows)
		}
		p.Rows = append(p.Rows, controllerPositionOf(o))
	}
	if p.Index < 0 {
		return nil, errors.New("missing firewall placement target")
	}
	return p, nil
}
func controllerValidatePlacement(s controllerStep) error {
	if s.Placement == nil {
		if s.Attempted && s.Change.Action == "delete" && s.Change.Before != nil && controllerOrdered(s.Change.Before.Path) {
			return errors.New("ordered deletion journal lacks placement")
		}
		return nil
	}
	p := s.Placement
	if s.Change.Action != "delete" || s.Change.Before == nil || !controllerOrdered(s.Change.Before.Path) || len(p.Rows) == 0 || len(p.Rows) > 4096 || p.Index < 0 || p.Index >= len(p.Rows) {
		return errors.New("invalid placement journal")
	}
	ids := map[string]bool{}
	for _, r := range p.Rows {
		digest, e := hex.DecodeString(r.Digest)
		if e != nil || len(digest) != 32 || !strings.HasPrefix(r.ID, "*") || strings.ContainsAny(r.ID, "/?#\\") || ids[r.ID] || !strings.HasPrefix(r.Key, s.Change.Before.Path+"|") {
			return errors.New("invalid placement anchor")
		}
		ids[r.ID] = true
	}
	target := p.Rows[p.Index]
	if target.ID != s.Change.Before.ID || target.Key != key(*s.Change.Before) || target.Digest != controllerPositionOf(*s.Change.Before).Digest {
		return errors.New("placement target does not match journal change")
	}
	return nil
}

// Exact surviving order and configurable state must match. Native IDs changed by
// earlier compensating PUTs are accepted only for journal-known owned deletions.
func controllerCheckPlacement(rows []Object, j controllerJournal, s controllerStep, restored bool) (string, error) {
	if e := controllerValidatePlacement(s); e != nil {
		return "", e
	}
	p := s.Placement
	actual := []Object{}
	for _, o := range rows {
		if o.Path == s.Change.Before.Path {
			actual = append(actual, o)
		}
	}
	expected := len(p.Rows)
	if !restored {
		expected--
	}
	if len(actual) != expected {
		return "", errors.New("firewall placement changed; recovery refused")
	}
	n := 0
	anchor := ""
	for i, want := range p.Rows {
		if !restored && i == p.Index {
			continue
		}
		got := controllerPositionOf(actual[n])
		knownRestored := false
		if got.ID != want.ID && got.Key == want.Key && got.Digest == want.Digest {
			for _, step := range j.Changes {
				if step.Attempted && step.Change.Action == "delete" && step.Change.Before != nil && step.Change.Before.ID == want.ID && key(*step.Change.Before) == want.Key && Owned(j.Instance, actual[n]) && controllerSame(actual[n], *step.Change.Before) {
					knownRestored = true
					break
				}
			}
		}
		if got.Key != want.Key || got.Digest != want.Digest || (got.ID != want.ID && !knownRestored) {
			return "", errors.New("firewall anchor changed; recovery refused")
		}
		if !restored && i == p.Index+1 {
			anchor = actual[n].ID
		}
		n++
	}
	return anchor, nil
}
