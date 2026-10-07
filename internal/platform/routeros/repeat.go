//go:build linux || darwin

package routeros

import (
	"errors"
	"reflect"
)

// A repeated reviewed transaction is a no-op only when its exact committed
// journal and all native realized identities still match. This retains rollback.
func (c *LabController) repeated(rows []Object, j *controllerJournal, p ChangePlan) (bool, error) {
	if j == nil || j.State != "committed" || j.Instance != p.Instance || len(j.Changes) != len(p.Changes) || len(p.Changes) == 0 {
		return false, nil
	}
	for i, raw := range p.Changes {
		ch := raw
		if ch.Before != nil {
			o := controllerProjection(*ch.Before)
			ch.Before = &o
		}
		if !reflect.DeepEqual(ch, j.Changes[i].Change) {
			return false, nil
		}
	}
	for _, step := range j.Changes {
		a, err := controllerFind(rows, changeKey(step.Change))
		if err != nil {
			return true, err
		}
		if step.Change.Action == "delete" {
			if a != nil {
				return true, errors.New("repeated transaction conflicts with recreated object")
			}
			continue
		}
		if a == nil || step.Realized == nil || a.ID != step.Realized.ID || !controllerSame(*a, *step.Realized) {
			return true, errors.New("repeated transaction conflicts with external edit")
		}
		if step.Change.After.PlaceBefore != "" {
			if err = verifyObjectPlacement(rows, *step.Change.After, a); err != nil {
				return true, err
			}
		}
	}
	return true, nil
}
