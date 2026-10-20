package subscriptions

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DialContext is trusted composition, never an arbitrary proxy URL from HTTP.
// The downloader validates and pins every destination before calling it.
type DialContext func(context.Context, string, string) (net.Conn, error)

// HTTPProxyDialer accepts only an authenticated loopback HTTP proxy. CONNECT
// carries a literal destination; HTTPS verification stays in the downloader.
func HTTPProxyDialer(proxy *url.URL) (DialContext, error) {
	invalid := errors.New("isolated proxy unavailable")
	if proxy == nil || proxy.Scheme != "http" || proxy.User == nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, invalid
	}
	host, port, err := net.SplitHostPort(proxy.Host)
	ip, parseErr := netip.ParseAddr(host)
	n, portErr := strconv.Atoi(port)
	password, hasPassword := proxy.User.Password()
	user := proxy.User.Username()
	if err != nil || parseErr != nil || !ip.IsLoopback() || ip.Zone() != "" || portErr != nil || n < 1 || n > 65535 || !hasPassword || user == "" || len(user) > 255 || len(password) < 1 || len(password) > 255 || strings.ContainsAny(user+password, "\r\n\x00") || strings.Contains(user, ":") {
		return nil, invalid
	}
	address := proxy.Host
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	return func(ctx context.Context, network, destination string) (result net.Conn, dialErr error) {
		defer func() {
			if dialErr != nil && ctx.Err() != nil {
				dialErr = ctx.Err()
			}
		}()
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, invalid
		}
		dh, dp, err := net.SplitHostPort(destination)
		dip, pe := netip.ParseAddr(dh)
		dpn, de := strconv.Atoi(dp)
		if err != nil || pe != nil || dip.Zone() != "" || dip.IsUnspecified() || dip.IsMulticast() || de != nil || dpn < 1 || dpn > 65535 {
			return nil, invalid
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, invalid
		}
		ok := false
		defer func() {
			if !ok {
				conn.Close()
			}
		}()
		if deadline, found := ctx.Deadline(); found {
			if conn.SetDeadline(deadline) != nil {
				return nil, invalid
			}
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", destination, destination, auth); err != nil {
			return nil, invalid
		}
		reader := bufio.NewReaderSize(conn, 4096)
		var header strings.Builder
		for {
			line, err := reader.ReadSlice('\n')
			if err != nil || header.Len()+len(line) > 16<<10 {
				return nil, invalid
			}
			header.Write(line)
			if string(line) == "\r\n" {
				break
			}
		}
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(header.String())), &http.Request{Method: http.MethodConnect})
		if err != nil || response.StatusCode != http.StatusOK || ctx.Err() != nil {
			return nil, invalid
		}
		if conn.SetDeadline(time.Time{}) != nil {
			return nil, invalid
		}
		ok = true
		return &proxyConnection{Conn: conn, reader: reader}, nil
	}, nil
}

type proxyConnection struct {
	net.Conn
	reader *bufio.Reader
}

func (c *proxyConnection) Read(p []byte) (int, error) { return c.reader.Read(p) }
