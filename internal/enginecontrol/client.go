// Package enginecontrol is the private, bounded sing-box Clash API bridge.
package enginecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Proxy struct {
	Type    string    `json:"type"`
	Now     string    `json:"now"`
	All     []string  `json:"all"`
	History []History `json:"history"`
}
type History struct {
	Time  time.Time `json:"time"`
	Delay int64     `json:"delay"`
}
type Client struct {
	address, secret string
	http            *http.Client
}

func New(address, secret string) (*Client, error) {
	host, port, e := net.SplitHostPort(address)
	ip, err := netip.ParseAddr(host)
	p, pe := strconv.Atoi(port)
	if e != nil || err != nil || !ip.IsLoopback() || pe != nil || p < 1 || p > 65535 || len(secret) < 32 || len(secret) > 256 || strings.ContainsAny(secret, "\x00\r\n") {
		return nil, errors.New("invalid private engine controller")
	}
	return &Client{address: "http://" + address, secret: secret, http: &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, e := json.Marshal(in)
		if e != nil {
			return errors.New("engine request invalid")
		}
		body = bytes.NewReader(raw)
	}
	r, e := http.NewRequestWithContext(ctx, method, c.address+path, body)
	if e != nil {
		return errors.New("engine request invalid")
	}
	r.Header.Set("Authorization", "Bearer "+c.secret)
	r.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(r)
	if e != nil {
		return errors.New("engine unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("engine request failed")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 {
		return errors.New("engine response invalid")
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("engine response invalid")
	}
	return nil
}
func (c *Client) Snapshot(ctx context.Context) (map[string]Proxy, error) {
	var result struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	e := c.request(ctx, "GET", "/proxies", nil, &result)
	if e == nil && result.Proxies == nil {
		e = errors.New("engine response invalid")
	}
	return result.Proxies, e
}
func (c *Client) Select(ctx context.Context, group, node string) error {
	return c.request(ctx, "PUT", "/proxies/"+url.PathEscape(group), map[string]string{"name": node}, nil)
}
func (c *Client) Delay(ctx context.Context, node string) (int64, error) {
	var result struct {
		Delay int64 `json:"delay"`
	}
	e := c.request(ctx, "GET", "/proxies/"+url.PathEscape(node)+"/delay?timeout=5000&url="+url.QueryEscape("https://www.gstatic.com/generate_204"), nil, &result)
	if e == nil && (result.Delay < 0 || result.Delay > 60000) {
		e = errors.New("engine response invalid")
	}
	return result.Delay, e
}
