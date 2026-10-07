// Package health probes the selected outbound independently of local readiness.
package health

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Checker reports success only when its configured end-to-end condition holds.
type Checker interface{ Check(context.Context) error }

// HTTPProbeConfig describes a controlled canary. ExpectedPeerIP checks the IP
// observed by that canary, so a successful DIRECT fallback cannot pass the probe.
// Plain HTTP is intended for isolated labs; use HTTPS and a trusted canary outside them.
type HTTPProbeConfig struct {
	SOCKSAddress   string
	URL            string
	ExpectedPeerIP string
	ExpectedStatus int
	Timeout        time.Duration
}

type HTTPProbe struct {
	config HTTPProbeConfig
	client *http.Client
}

func NewHTTPProbe(c HTTPProbeConfig) (*HTTPProbe, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid canary URL")
	}
	if _, _, err := net.SplitHostPort(c.SOCKSAddress); err != nil {
		return nil, errors.New("invalid SOCKS address")
	}
	if net.ParseIP(c.ExpectedPeerIP) == nil {
		return nil, errors.New("invalid expected canary peer IP")
	}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Second
	}
	if c.Timeout < 0 {
		return nil, errors.New("invalid probe timeout")
	}
	if c.ExpectedStatus == 0 {
		c.ExpectedStatus = http.StatusOK
	}
	if c.ExpectedStatus < 100 || c.ExpectedStatus > 599 {
		return nil, errors.New("invalid expected HTTP status")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialSOCKS(ctx, c.SOCKSAddress, address)
		},
		DisableKeepAlives: true, // Every sample must establish a fresh proxy path.
	}
	return &HTTPProbe{config: c, client: &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (p *HTTPProbe) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.URL, nil)
	if err != nil {
		return errors.New("canary request invalid")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("canary transport failed") // Never propagate URLs or raw credentials.
	}
	defer resp.Body.Close()
	if resp.StatusCode != p.config.ExpectedStatus {
		return errors.New("canary HTTP status mismatch")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(body) > 4096 {
		return errors.New("canary response invalid")
	}
	var result struct {
		RemoteIP string `json:"remote_ip"`
	}
	if json.Unmarshal(body, &result) != nil {
		return errors.New("canary response invalid")
	}
	actual := net.ParseIP(result.RemoteIP)
	if actual == nil || !actual.Equal(net.ParseIP(p.config.ExpectedPeerIP)) {
		return errors.New("canary egress mismatch")
	}
	return nil
}

// dialSOCKS uses domain requests, leaving DNS resolution to the selected proxy.
// This implementation deliberately accepts only unauthenticated local SOCKS5.
func dialSOCKS(ctx context.Context, endpoint, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid SOCKS destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid SOCKS destination")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	write := func(data []byte) error {
		for len(data) > 0 {
			n, e := conn.Write(data)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
		return nil
	}
	if err = write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(conn, greeting); err != nil {
		return nil, err
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return nil, errors.New("SOCKS authentication unsupported")
	}
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, []byte(host)...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if err = write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, errors.New("SOCKS connect rejected")
	}
	size := 0
	switch header[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		size = int(length[0])
		if size == 0 {
			return nil, errors.New("SOCKS bound address empty")
		}
	default:
		return nil, fmt.Errorf("SOCKS address type unsupported")
	}
	if _, err = io.CopyN(io.Discard, conn, int64(size+2)); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}
