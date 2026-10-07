package routeros

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AppInstallation is a deliberately narrow, read-only projection. YAML,
// environment and generated secrets are not requested. Command overrides are
// checked for absence by the reviewer and are never retained in an artifact.
// This inventory never expands the controller's mutable resource allowlist.
type AppInstallation struct {
	Resource   map[string]string   `json:"resource"`
	Apps       []map[string]string `json:"apps"`
	Containers []map[string]string `json:"containers"`
	VETHs      []map[string]string `json:"veths"`
}

var appInstallationFields = map[string][]string{
	"system/resource": {"version", "architecture-name", "board-name"},
	"app":             {".id", "name", "interface", "ip-address", "required-mounts", "disabled", "running", "network", "default-network", "firewall-redirects", "container-command-lines"},
	"container":       {".id", "name", "interface", "root-dir", "remote-image", "image-id", "mount", "privileged", "stopped", "running", "check-certificate", "entrypoint", "default-entrypoint", "cmd", "default-cmd"},
	"interface/veth":  {".id", "name", "address", "gateway", "dhcp", "disabled"},
}

func (c *Client) appInstallationGET(ctx context.Context, path string) ([]map[string]string, error) {
	fields, ok := appInstallationFields[path]
	if !ok {
		return nil, errors.New("unsupported App installation resource")
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path
	u.RawQuery = url.Values{".proplist": {strings.Join(fields, ",")}}.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return nil, errors.New("invalid App installation request")
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return nil, readTransportError(e)
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if e != nil || len(data) > 4<<20 {
		return nil, errors.New("App installation response exceeds limit or cannot be read")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("App installation read failed (HTTP %d; body redacted)", response.StatusCode)
	}
	rows, e := scalarRows(data, path == "system/resource")
	if e != nil {
		return nil, errors.New("invalid App installation projection")
	}
	allowed := map[string]bool{}
	for _, field := range fields {
		allowed[field] = true
	}
	for _, row := range rows {
		for field := range row {
			if !allowed[field] {
				return nil, errors.New("unexpected App installation projection field")
			}
		}
	}
	return rows, nil
}

func (c *Client) InspectAppInstallation(ctx context.Context) (AppInstallation, error) {
	var snapshot AppInstallation
	resource, e := c.appInstallationGET(ctx, "system/resource")
	if e != nil {
		return snapshot, e
	}
	snapshot.Resource = resource[0]
	if snapshot.Apps, e = c.appInstallationGET(ctx, "app"); e != nil {
		return snapshot, e
	}
	if snapshot.Containers, e = c.appInstallationGET(ctx, "container"); e != nil {
		return snapshot, e
	}
	if snapshot.VETHs, e = c.appInstallationGET(ctx, "interface/veth"); e != nil {
		return snapshot, e
	}
	return snapshot, nil
}
