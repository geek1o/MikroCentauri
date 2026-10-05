// Package dnsgate provides a bounded laboratory DNS publication gate. Its
// internal resolver owns FakeIP allocation; the gate never inserts cache rows.
package dnsgate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"mikrocentauri.local/core/internal/fakeip"
)

type Publisher interface {
	PublishAlias(context.Context, string, netip.Addr) (fakeip.Mapping, time.Duration, error)
}

// Event describes a terminal request outcome without packets or error strings.
// Domain is populated only after a valid query matches the configured selected
// names. Duration measures the complete Handle call before observer delivery.
type Event struct {
	Stage    string
	Reason   string
	Domain   string
	Duration time.Duration
}

type Config struct {
	InternalAddress string
	Selected        []string
	MaxMessage      int
	Timeout         time.Duration
	// Observe runs synchronously once per Handle call, including failures. It
	// must be quick and safe for concurrent calls. Observer panics are ignored
	// so diagnostics cannot replace a validated DNS response.
	Observe func(Event)
}

type Gate struct {
	config    Config
	publisher Publisher
	selected  map[string]bool
}

var aliasRange = netip.MustParsePrefix("198.18.0.0/15")

func New(c Config, p Publisher) (*Gate, error) {
	if p == nil {
		return nil, errors.New("DNS publication requires a publisher")
	}
	if c.MaxMessage == 0 {
		c.MaxMessage = 4096
	}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Second
	}
	if c.MaxMessage < 512 || c.MaxMessage > 4096 || c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return nil, errors.New("invalid DNS gate bounds")
	}
	host, _, err := net.SplitHostPort(c.InternalAddress)
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !ip.IsLoopback() {
		return nil, errors.New("internal DNS must use a loopback address")
	}
	g := &Gate{config: c, publisher: p, selected: make(map[string]bool)}
	for _, name := range c.Selected {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !validName(name) {
			return nil, errors.New("invalid selected DNS name")
		}
		g.selected[name] = true
	}
	if len(g.selected) == 0 {
		return nil, errors.New("selected DNS names are required")
	}
	return g, nil
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// Handle returns only an answer whose selected alias has passed publication.
// Resolver and publisher failures deliberately share the same DNS SERVFAIL.
func (g *Gate) Handle(ctx context.Context, request []byte) []byte {
	started := time.Now()
	event := Event{Stage: "request", Reason: "invalid_query"}
	defer func() {
		event.Duration = time.Since(started)
		g.observe(event)
	}()
	q, err := parse(request, g.config.MaxMessage)
	if err != nil || q.flags&0x8000 != 0 || q.flags&0x7800 != 0 || q.flags&0x0200 != 0 || len(q.questions) != 1 || len(q.answers) != 0 || len(q.authority) != 0 {
		return failure(request, nil)
	}
	question := q.questions[0]
	selected := g.selected[question.name]
	if selected {
		event.Domain = question.name
	}
	if selected && question.class != 1 {
		event.Reason = "unsupported_class"
		return failure(request, &question)
	}
	if selected && question.kind == 28 {
		event.Reason = "selected_aaaa_empty"
		return response(request, question, nil, 0)
	}
	if selected && question.kind != 1 {
		event.Reason = "unsupported_type"
		return failure(request, &question)
	}
	ctx, cancel := context.WithTimeout(ctx, g.config.Timeout)
	defer cancel()
	event.Stage = "internal_exchange"
	raw, err := g.exchange(ctx, request)
	if err != nil {
		event.Reason = failureReason(ctx, err, "transport_error")
		if errors.Is(err, errInvalidFrame) {
			event.Reason = "invalid_response"
		}
		return failure(request, &question)
	}
	r, err := parse(raw, g.config.MaxMessage)
	if err != nil || r.id != q.id || r.flags&0x8000 == 0 || r.flags&0x7800 != 0 || r.flags&0x0200 != 0 || len(r.questions) != 1 || r.questions[0] != question {
		event.Reason = "invalid_response"
		return failure(request, &question)
	}
	if selected {
		if r.flags&15 != 0 {
			event.Reason = "upstream_rcode"
			return failure(request, &question)
		}
		event.Stage, event.Reason = "alias_validation", "invalid_answer"
		if len(r.answers) != 1 {
			return failure(request, &question)
		}
		a := r.answers[0]
		if a.name != question.name || a.kind != 1 || a.class != 1 || len(a.data) != 4 {
			return failure(request, &question)
		}
		alias := netip.AddrFrom4([4]byte{a.data[0], a.data[1], a.data[2], a.data[3]})
		if !aliasRange.Contains(alias) {
			event.Reason = "outside_alias_range"
			return failure(request, &question)
		}
		event.Stage = "publication"
		mapping, lease, err := g.publisher.PublishAlias(ctx, question.name, alias)
		if err != nil || ctx.Err() != nil {
			event.Reason = publicationFailureReason(ctx, err)
			return failure(request, &question)
		}
		if lease <= 0 || mapping.Domain != question.name || mapping.Fake != alias || !mapping.Real.Is4() || mapping.Real.IsUnspecified() || mapping.Real.IsMulticast() || aliasRange.Contains(mapping.Real) {
			event.Reason = "receipt_mismatch"
			return failure(request, &question)
		}
		ttl := a.ttl
		seconds := uint64(lease / time.Second)
		if seconds < uint64(ttl) {
			ttl = uint32(seconds)
		}
		event.Reason = "selected_published"
		return response(request, question, a.data, ttl)
	}
	// Never let an unselected answer bypass the publication protocol. Check all
	// sections, including additional records which clients may cache.
	event.Stage = "alias_validation"
	for _, section := range [][]record{r.answers, r.authority, r.additional} {
		for _, a := range section {
			if a.kind == 1 {
				if len(a.data) != 4 {
					event.Reason = "invalid_answer"
					return failure(request, &question)
				}
				if aliasRange.Contains(netip.AddrFrom4([4]byte{a.data[0], a.data[1], a.data[2], a.data[3]})) {
					event.Reason = "unselected_alias_leak"
					return failure(request, &question)
				}
			}
		}
	}
	event.Stage, event.Reason = "internal_exchange", "unselected_forwarded"
	return raw
}

func failureReason(ctx context.Context, err error, fallback string) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "deadline"
	}
	return fallback
}

func publicationFailureReason(ctx context.Context, err error) string {
	reason := failureReason(ctx, err, "publisher_error")
	if reason != "publisher_error" {
		return reason
	}
	var operation *fakeip.OperationError
	if errors.As(err, &operation) {
		switch operation.Operation {
		case "resolve", "ensure", "update", "verify", "persist":
			return operation.Operation + "_error"
		}
	}
	return reason
}

func (g *Gate) observe(event Event) {
	if g.config.Observe != nil {
		defer func() { _ = recover() }()
		g.config.Observe(event)
	}
}

var errInvalidFrame = errors.New("internal DNS frame outside bounds")

func (g *Gate) exchange(ctx context.Context, query []byte) ([]byte, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", g.config.InternalAddress)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet, uint16(len(query)))
	copy(packet[2:], query)
	if err = writeAll(c, packet); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err = io.ReadFull(c, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 || n > g.config.MaxMessage {
		return nil, errInvalidFrame
	}
	answer := make([]byte, n)
	_, err = io.ReadFull(c, answer)
	return answer, err
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
