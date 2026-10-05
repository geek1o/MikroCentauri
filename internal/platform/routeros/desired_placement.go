//go:build linux || darwin

package routeros

import "errors"

func controllerCreateFields(o Object) map[string]string {
	f := map[string]string{}
	for k, v := range o.Fields {
		f[k] = v
	}
	if o.PlaceBefore != "" {
		f["place-before"] = o.PlaceBefore
	}
	return f
}
func validateDesiredPlacement(rows []Object, o Object) error {
	var actual *Object
	found := false
	for _, r := range rows {
		if r.Path != o.Path {
			continue
		}
		if r.ID == o.PlaceBefore {
			if r.Fields["dynamic"] == "true" {
				return errors.New("dynamic placement anchor refused")
			}
			found = true
		}
		if key(r) == key(o) {
			x := r
			actual = &x
		}
	}
	if !found {
		return errors.New("placement anchor missing")
	}
	if actual != nil {
		return verifyObjectPlacement(rows, o, actual)
	}
	return nil
}
func verifyObjectPlacement(rows []Object, desired Object, actual *Object) error {
	if actual == nil {
		return errors.New("placement object absent")
	}
	previous := ""
	for _, r := range rows {
		if r.Path != desired.Path {
			continue
		}
		if r.ID == desired.PlaceBefore {
			if previous == actual.ID {
				return nil
			}
			return errors.New("existing rule placement differs; explicit replacement required")
		}
		previous = r.ID
	}
	return errors.New("placement anchor disappeared")
}
