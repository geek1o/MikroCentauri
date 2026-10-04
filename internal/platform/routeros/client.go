package routeros

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client refuses cleartext outside an explicit lab constructor. TLS uses system/custom transport trust.
type Client struct {
	base           *url.URL
	user, password string
	http           *http.Client
}

func NewClient(base, user, password string, client *http.Client) (*Client, error) {
	return newClient(base, user, password, client, false)
}
func NewLabClient(base, user, password string, client *http.Client) (*Client, error) {
	return newClient(base, user, password, client, true)
}
func newClient(base, user, password string, client *http.Client, lab bool) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (!lab && u.Scheme != "https") || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSuffix(u.Path, "/") != "/rest" {
		return nil, errors.New("RouterOS base must be credential-free HTTPS /rest URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{u, user, password, &clone}, nil
}
func (c *Client) request(ctx context.Context, method, path, id string, fields map[string]string) ([]byte, error) {
	if !paths[path] {
		return nil, errors.New("unsupported RouterOS resource")
	}
	if id != "" && (!strings.HasPrefix(id, "*") || strings.ContainsAny(id, "/?#\\")) {
		return nil, errors.New("invalid RouterOS object ID")
	}
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + path
	if id != "" {
		u.Path += "/" + id
		// RouterOS REST does not accept percent-encoded '*' in object IDs.
		// Preserve that literal character while escaping every other path byte.
		u.RawPath = strings.ReplaceAll(u.EscapedPath(), "%2A", "*")
	}
	var body io.Reader
	if fields != nil {
		b, e := json.Marshal(fields)
		if e != nil {
			return nil, e
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), body)
	if e != nil {
		return nil, errors.New("cannot build RouterOS request")
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return nil, errors.New("RouterOS transport failed")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4<<20+1))
	if e != nil || len(b) > 4<<20 {
		return nil, errors.New("RouterOS response exceeds limit")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("RouterOS request failed (HTTP %d; body redacted)", res.StatusCode)
	}
	return b, nil
}
func (c *Client) Discover(ctx context.Context) ([]Object, error) {
	return c.discover(ctx, []string{"ip/route", "ip/firewall/nat", "ip/firewall/mangle", "ip/firewall/filter", "tool/netwatch"})
}

func (c *Client) discover(ctx context.Context, ordered []string) ([]Object, error) {
	var result []Object
	for _, path := range ordered {
		b, e := c.request(ctx, "GET", path, "", nil)
		if e != nil {
			return nil, e
		}
		var rows []map[string]any
		if e = json.Unmarshal(b, &rows); e != nil {
			return nil, errors.New("invalid RouterOS response")
		}
		for _, row := range rows {
			f := map[string]string{}
			id := ""
			for k, v := range row {
				if k == ".id" {
					id = fmt.Sprint(v)
				} else {
					f[k] = fmt.Sprint(v)
				}
			}
			result = append(result, Object{Path: path, ID: id, Fields: f})
		}
	}
	return result, nil
}

// ApplyLab is intentionally unavailable to the product CLI. Mock/lab only until dataplane gates pass.
// Every successful mutation has a compensating operation; rollback failures are reported.
func (c *Client) ApplyLab(ctx context.Context, p ChangePlan) error {
	var undo []func(context.Context) error
	rollback := func(cause error) error {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for i := len(undo) - 1; i >= 0; i-- {
			if e := undo[i](rctx); e != nil {
				cause = errors.Join(cause, fmt.Errorf("rollback failed: %w", e))
			}
		}
		return cause
	}
	// Prevent forged plans and verify fresh ownership before any mutation. Concurrent writes remain unsupported.
	actual, e := c.Discover(ctx)
	if e != nil {
		return e
	}
	current := map[string]Object{}
	for _, o := range actual {
		current[o.Path+"|"+o.ID] = o
	}
	seen := map[string]bool{}
	for _, ch := range p.Changes {
		if ch.Action != "create" && ch.Action != "update" && ch.Action != "delete" {
			return errors.New("invalid action")
		}
		if (ch.Action == "create" && (ch.Before != nil || ch.After == nil)) || (ch.Action == "delete" && (ch.Before == nil || ch.After != nil)) || (ch.Action == "update" && (ch.Before == nil || ch.After == nil)) {
			return errors.New("invalid change shape")
		}
		for _, o := range []*Object{ch.Before, ch.After} {
			if o != nil && !Owned(p.Instance, *o) {
				return errors.New("unsafe change ownership")
			}
		}
		if ch.Before != nil {
			fresh, ok := current[ch.Before.Path+"|"+ch.Before.ID]
			if !ok || !EqualManaged(fresh, *ch.Before) {
				return errors.New("stale plan; rediscovery required")
			}
		}
		if ch.After != nil && ch.After.ID != "" {
			return errors.New("unsafe desired object ID")
		}
		if ch.Before != nil && ch.After != nil && key(*ch.Before) != key(*ch.After) {
			return errors.New("cannot transfer object ownership")
		}
		k := changeKey(ch)
		if seen[k] {
			return errors.New("duplicate plan change")
		}
		seen[k] = true
		if ch.Action == "create" {
			for _, o := range actual {
				if key(o) == key(*ch.After) {
					return errors.New("create conflicts with existing ownership")
				}
			}
		}
	}
	for _, ch := range p.Changes {
		switch ch.Action {
		case "create":
			a := *ch.After
			b, e := c.request(ctx, "PUT", a.Path, "", a.Fields)
			if e != nil {
				return rollback(e)
			}
			var row map[string]string
			if json.Unmarshal(b, &row) != nil || row[".id"] == "" {
				return rollback(errors.New("create returned no ID; manual rediscovery required"))
			}
			id := row[".id"]
			undo = append(undo, func(x context.Context) error { _, e := c.request(x, "DELETE", a.Path, id, nil); return e })
		case "update":
			old := *ch.Before
			fields := map[string]string{}
			for k := range ch.After.Fields {
				fields[k] = old.Fields[k]
			}
			if _, e := c.request(ctx, "PATCH", old.Path, old.ID, ch.After.Fields); e != nil {
				return rollback(e)
			}
			undo = append(undo, func(x context.Context) error { _, e := c.request(x, "PATCH", old.Path, old.ID, fields); return e })
		case "delete":
			old := *ch.Before
			if _, e := c.request(ctx, "DELETE", old.Path, old.ID, nil); e != nil {
				return rollback(e)
			}
			undo = append(undo, func(x context.Context) error {
				fields := map[string]string{}
				for k, v := range old.Fields {
					if k != "dynamic" && k != "active" && k != "invalid" {
						fields[k] = v
					}
				}
				_, e := c.request(x, "PUT", old.Path, "", fields)
				return e
			})
		}
	}
	return nil
}
