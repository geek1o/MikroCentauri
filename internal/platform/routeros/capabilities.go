package routeros

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Capabilities is read-only evidence. Resource availability proves neither write
// permission nor device-mode, TUN, placement, or production activation readiness.
type Capabilities struct {
	Version              string          `json:"version"`
	Architecture         string          `json:"architecture"`
	Board                string          `json:"board"`
	Platform             string          `json:"platform"`
	Packages             []Package       `json:"packages"`
	Resources            map[string]bool `json:"resources"`
	Interfaces           []Interface     `json:"interfaces"`
	VersionSupported     bool            `json:"version_supported"`
	VersionSupportReason string          `json:"version_support_reason"`
}
type Package struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Disabled bool   `json:"disabled"`
}
type Interface struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Disabled bool   `json:"disabled"`
	Running  bool   `json:"running"`
}

var capabilityPaths = map[string]bool{"system/resource": true, "system/package": true, "interface": true}
var managedCapabilityPaths = []string{"ip/route", "ip/firewall/nat", "ip/firewall/mangle", "ip/firewall/filter", "tool/netwatch", "system/scheduler"}
var routerVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:beta[0-9]+|rc[0-9]+)?(?: \((?:stable|testing|development|long-term)\))?$`)

// capabilityGET has a separate GET-only allowlist; it never widens mutation paths.
func (c *Client) capabilityGET(ctx context.Context, path string) ([]byte, bool, error) {
	if !capabilityPaths[path] && !paths[path] {
		return nil, false, errors.New("unsupported RouterOS capability resource")
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, errors.New("cannot build RouterOS capability request")
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, errors.New("RouterOS capability transport failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	if err != nil || len(body) > 4<<20 {
		return nil, false, errors.New("RouterOS capability response exceeds limit or cannot be read")
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, false, fmt.Errorf("RouterOS capability request failed (HTTP %d; body redacted)", res.StatusCode)
	}
	return body, true, nil
}

// scalarRows enforces bounded string-valued REST records, rejects duplicate keys,
// nested values, nulls and trailing JSON. RouterOS REST encodes scalar values as strings.
func scalarRows(body []byte, singleton bool) ([]map[string]string, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	first, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid RouterOS capability JSON")
	}
	var rows []map[string]string
	row := func() (map[string]string, error) {
		result := map[string]string{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok || len(key) > 256 || len(result) >= 256 {
				return nil, errors.New("invalid field")
			}
			if _, exists := result[key]; exists {
				return nil, errors.New("duplicate field")
			}
			v, e := d.Token()
			if e != nil {
				return nil, e
			}
			value, ok := v.(string)
			limit := 4096
			if key == "test-script" || key == "down-script" || key == "up-script" || key == "on-event" {
				limit = 32 << 10
			}
			if !ok || len(value) > limit {
				return nil, errors.New("invalid scalar")
			}
			result[key] = value
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, errors.New("invalid record")
		}
		return result, nil
	}
	if first == json.Delim('{') && singleton {
		r, e := row()
		if e != nil {
			return nil, errors.New("invalid RouterOS capability record")
		}
		rows = append(rows, r)
	} else if first == json.Delim('[') {
		for d.More() {
			if len(rows) >= 4096 {
				return nil, errors.New("RouterOS capability record limit exceeded")
			}
			start, e := d.Token()
			if e != nil || start != json.Delim('{') {
				return nil, errors.New("invalid RouterOS capability record")
			}
			r, e := row()
			if e != nil {
				return nil, errors.New("invalid RouterOS capability record")
			}
			rows = append(rows, r)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, errors.New("invalid RouterOS capability array")
		}
	} else {
		return nil, errors.New("invalid RouterOS capability shape")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing RouterOS capability JSON")
	}
	if singleton && len(rows) != 1 {
		return nil, errors.New("RouterOS system resource requires exactly one record")
	}
	if rows == nil {
		rows = []map[string]string{}
	}
	return rows, nil
}
func capabilityString(row map[string]string, key string) (string, error) {
	value, ok := row[key]
	if !ok || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("missing or invalid RouterOS capability field")
	}
	return value, nil
}
func capabilityBool(row map[string]string, key string) (bool, error) {
	switch row[key] {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("missing or invalid RouterOS capability boolean")
	}
}
func capabilityVersion(row map[string]string) (string, error) {
	v, e := capabilityString(row, "version")
	if e != nil || !routerVersion.MatchString(v) {
		return "", errors.New("missing or invalid RouterOS version")
	}
	return v, nil
}
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	result := Capabilities{Packages: []Package{}, Interfaces: []Interface{}, Resources: map[string]bool{}}
	fetch := func(path string, single bool) ([]map[string]string, error) {
		b, available, e := c.capabilityGET(ctx, path)
		if e != nil {
			return nil, e
		}
		if !available {
			return nil, errors.New("required RouterOS capability resource unavailable")
		}
		return scalarRows(b, single)
	}
	rows, e := fetch("system/resource", true)
	if e != nil {
		return Capabilities{}, e
	}
	r := rows[0]
	if result.Version, e = capabilityVersion(r); e != nil {
		return Capabilities{}, e
	}
	for _, field := range []struct {
		key string
		out *string
	}{{"architecture-name", &result.Architecture}, {"board-name", &result.Board}, {"platform", &result.Platform}} {
		*field.out, e = capabilityString(r, field.key)
		if e != nil {
			return Capabilities{}, e
		}
	}
	rows, e = fetch("system/package", false)
	if e != nil {
		return Capabilities{}, e
	}
	seen := map[string]bool{}
	for _, r := range rows {
		var p Package
		if p.Name, e = capabilityString(r, "name"); e != nil {
			return Capabilities{}, e
		}
		if seen[p.Name] {
			return Capabilities{}, errors.New("duplicate RouterOS package")
		}
		seen[p.Name] = true
		if p.Version, e = capabilityVersion(r); e != nil {
			return Capabilities{}, e
		}
		if p.Disabled, e = capabilityBool(r, "disabled"); e != nil {
			return Capabilities{}, e
		}
		result.Packages = append(result.Packages, p)
	}
	rows, e = fetch("interface", false)
	if e != nil {
		return Capabilities{}, e
	}
	seen = map[string]bool{}
	for _, r := range rows {
		var i Interface
		if i.Name, e = capabilityString(r, "name"); e != nil {
			return Capabilities{}, e
		}
		if seen[i.Name] {
			return Capabilities{}, errors.New("duplicate RouterOS interface")
		}
		seen[i.Name] = true
		if i.Type, e = capabilityString(r, "type"); e != nil {
			return Capabilities{}, e
		}
		if i.Disabled, e = capabilityBool(r, "disabled"); e != nil {
			return Capabilities{}, e
		}
		if i.Running, e = capabilityBool(r, "running"); e != nil {
			return Capabilities{}, e
		}
		result.Interfaces = append(result.Interfaces, i)
	}
	for _, path := range managedCapabilityPaths {
		b, available, e := c.capabilityGET(ctx, path)
		if e != nil {
			return Capabilities{}, e
		}
		if available {
			if _, e = scalarRows(b, false); e != nil {
				return Capabilities{}, e
			}
		}
		result.Resources[path] = available
	}
	result.VersionSupported = (result.Version == "7.24.5" || result.Version == "7.24.5 (stable)") && (result.Board == "CHR" || strings.HasPrefix(result.Board, "CHR ")) && result.Architecture == "x86_64" && result.Platform == "MikroTik"
	result.VersionSupportReason = "outside the verified CHR x86_64 RouterOS 7.24.5 laboratory profile; production activation remains blocked"
	if result.VersionSupported {
		result.VersionSupportReason = "matches the verified CHR x86_64 RouterOS 7.24.5 laboratory profile; GET does not prove write permission, device-mode, TUN or production readiness"
	}
	return result, nil
}
