// Package realdns provides a bounded IPv4 DNS stub resolver for publication leases.
package realdns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

type Config struct {
	Address    string
	Timeout    time.Duration
	MaxMessage int
}
type Resolver struct{ cfg Config }

func New(cfg Config) (*Resolver, error) {
	a, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().Zone() != "" {
		return nil, errors.New("DNS upstream must be a literal unicast IP:port")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.MaxMessage == 0 {
		cfg.MaxMessage = 4096
	}
	if cfg.Timeout < 0 || cfg.Timeout > 30*time.Second || cfg.MaxMessage < 512 || cfg.MaxMessage > 4096 {
		return nil, errors.New("invalid DNS resolver bounds")
	}
	return &Resolver{cfg}, nil
}

func (r *Resolver) ResolveA(ctx context.Context, domain string) ([]netip.Addr, time.Duration, error) {
	domain, err := fakeip.CanonicalDomain(domain)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	id := make([]byte, 2)
	if _, err = rand.Read(id); err != nil {
		return nil, 0, err
	}
	q := make([]byte, 12)
	copy(q, id)
	q[2] = 1
	q[5] = 1
	q = appendName(q, domain)
	q = append(q, 0, 1, 0, 1)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", r.cfg.Address)
	if err != nil {
		return nil, 0, fmt.Errorf("DNS connect: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	frame = append(frame, q...)
	for len(frame) > 0 {
		n, e := conn.Write(frame)
		if e != nil {
			return nil, 0, fmt.Errorf("DNS write: %w", e)
		}
		if n == 0 {
			return nil, 0, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	var header [2]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, 0, fmt.Errorf("DNS frame: %w", err)
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n < 12 || n > r.cfg.MaxMessage {
		return nil, 0, errors.New("DNS frame exceeds bounds")
	}
	response := make([]byte, n)
	if _, err = io.ReadFull(conn, response); err != nil {
		return nil, 0, fmt.Errorf("DNS response: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return nil, 0, err
	}
	return resolve(response, binary.BigEndian.Uint16(id), domain)
}

var malformed = errors.New("malformed DNS response")

func appendName(b []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}
func nameAt(b []byte, start int) (string, int, error) {
	pos, next, size := start, -1, 1
	labels := []string{}
	seen := map[int]bool{}
	for steps := 0; steps < 128; steps++ {
		if pos < 0 || pos >= len(b) || seen[pos] {
			return "", 0, malformed
		}
		seen[pos] = true
		n := int(b[pos])
		pos++
		if n&0xc0 == 0xc0 {
			if pos >= len(b) {
				return "", 0, malformed
			}
			target := (n&0x3f)<<8 | int(b[pos])
			pos++
			if target >= pos-2 {
				return "", 0, malformed
			}
			if next < 0 {
				next = pos
			}
			pos = target
			continue
		}
		if n&0xc0 != 0 {
			return "", 0, malformed
		}
		if n == 0 {
			if next < 0 {
				next = pos
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		if pos+n > len(b) {
			return "", 0, malformed
		}
		size += n + 1
		if size > 255 {
			return "", 0, malformed
		}
		for _, c := range b[pos : pos+n] {
			if c < 33 || c > 126 || c == '.' {
				return "", 0, malformed
			}
		}
		labels = append(labels, string(b[pos:pos+n]))
		pos += n
	}
	return "", 0, malformed
}

type rr struct {
	owner       string
	kind, class uint16
	ttl         uint32
	data        []byte
	target      string
}

func resolve(b []byte, id uint16, domain string) ([]netip.Addr, time.Duration, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id {
		return nil, 0, malformed
	}
	flags := binary.BigEndian.Uint16(b[2:])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 || flags&0x0040 != 0 || flags&15 != 0 {
		return nil, 0, errors.New("DNS response flags or status rejected")
	}
	if binary.BigEndian.Uint16(b[4:]) != 1 {
		return nil, 0, malformed
	}
	name, off, err := nameAt(b, 12)
	if err != nil || off+4 > len(b) || name != domain || binary.BigEndian.Uint16(b[off:]) != 1 || binary.BigEndian.Uint16(b[off+2:]) != 1 {
		return nil, 0, malformed
	}
	off += 4
	answers := map[string][]rr{}
	total := 0
	for section := 0; section < 3; section++ {
		count := int(binary.BigEndian.Uint16(b[6+section*2:]))
		total += count
		if total > 256 {
			return nil, 0, malformed
		}
		for i := 0; i < count; i++ {
			owner, next, e := nameAt(b, off)
			if e != nil || next+10 > len(b) {
				return nil, 0, malformed
			}
			r := rr{owner: owner, kind: binary.BigEndian.Uint16(b[next:]), class: binary.BigEndian.Uint16(b[next+2:]), ttl: binary.BigEndian.Uint32(b[next+4:])}
			start := next + 10
			end := start + int(binary.BigEndian.Uint16(b[next+8:]))
			if end > len(b) {
				return nil, 0, malformed
			}
			r.data = b[start:end]
			if r.kind == 5 {
				target, after, e := nameAt(b, start)
				if e != nil || after != end {
					return nil, 0, malformed
				}
				r.target = target
			}
			if r.kind == 1 && len(r.data) != 4 {
				return nil, 0, malformed
			}
			if section == 0 {
				answers[owner] = append(answers[owner], r)
			}
			off = end
		}
	}
	if off != len(b) {
		return nil, 0, malformed
	}
	seen := map[string]bool{}
	ttl := uint32(1<<31 - 1)
	for hops := 0; hops <= 8; hops++ {
		if seen[domain] {
			return nil, 0, errors.New("DNS CNAME loop")
		}
		seen[domain] = true
		target := ""
		ips := []netip.Addr{}
		for _, r := range answers[domain] {
			if r.class != 1 || (r.kind != 1 && r.kind != 5) {
				continue
			}
			if r.ttl == 0 || r.ttl >= 1<<31 {
				return nil, 0, errors.New("DNS lease TTL rejected")
			}
			ttl = min(ttl, r.ttl)
			if r.kind == 5 {
				if r.target == "" || (target != "" && target != r.target) {
					return nil, 0, errors.New("conflicting DNS CNAME")
				}
				target = r.target
				continue
			}
			a := netip.AddrFrom4([4]byte(r.data))
			if a.IsUnspecified() || a.IsMulticast() || netip.MustParsePrefix("198.18.0.0/15").Contains(a) {
				return nil, 0, errors.New("unsafe DNS A address")
			}
			ips = append(ips, a)
		}
		if target != "" && len(ips) > 0 {
			return nil, 0, errors.New("DNS CNAME and A conflict")
		}
		if len(ips) > 0 {
			slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
			return slices.Compact(ips), time.Duration(ttl) * time.Second, nil
		}
		if target == "" || hops == 8 {
			return nil, 0, errors.New("DNS answer lacks bounded terminal A RRset")
		}
		domain = target
	}
	return nil, 0, malformed
}
