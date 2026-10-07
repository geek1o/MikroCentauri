package dnsgate

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"mikrocentauri.local/core/internal/fakeip"
	"net"
	"net/netip"
	"time"
)

// Allocator queries the stock engine's canonical loopback DNS namespace. Calling
// Alias may allocate; forwarded traffic must be quarantined during admission.
type Allocator struct{ gate Gate }

func NewAllocator(address string) (*Allocator, error) {
	host, port, err := net.SplitHostPort(address)
	a, e := netip.ParseAddr(host)
	if err != nil || e != nil || !a.IsLoopback() || port == "" {
		return nil, errors.New("allocator must use loopback DNS")
	}
	return &Allocator{gate: Gate{config: Config{InternalAddress: address, MaxMessage: 4096, Timeout: 2 * time.Second}}}, nil
}
func (a *Allocator) Alias(ctx context.Context, domain string) (netip.Addr, error) {
	domain, err := fakeip.CanonicalDomain(domain)
	if err != nil {
		return netip.Addr{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, a.gate.config.Timeout)
	defer cancel()
	request := make([]byte, 12)
	if _, err = rand.Read(request[:2]); err != nil {
		return netip.Addr{}, err
	}
	binary.BigEndian.PutUint16(request[2:], 0x0100)
	q := question{domain, 1, 1}
	request = canonicalQuery(request, q)
	raw, err := a.gate.exchange(ctx, request)
	if err != nil {
		return netip.Addr{}, err
	}
	m, err := parse(raw, 4096)
	if err != nil || m.id != binary.BigEndian.Uint16(request) || m.flags&0x8000 == 0 || m.flags&0x7800 != 0 || m.flags&0x0200 != 0 || m.flags&15 != 0 || len(m.questions) != 1 || m.questions[0] != q || len(m.answers) != 1 {
		return netip.Addr{}, errors.New("allocator response rejected")
	}
	r := m.answers[0]
	if r.name != domain || r.kind != 1 || r.class != 1 || len(r.data) != 4 {
		return netip.Addr{}, errors.New("allocator A rejected")
	}
	alias := netip.AddrFrom4([4]byte{r.data[0], r.data[1], r.data[2], r.data[3]})
	if !aliasRange.Contains(alias) || ctx.Err() != nil {
		return netip.Addr{}, errors.New("allocator alias rejected")
	}
	return alias, nil
}
