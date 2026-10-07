package dnsgate

import (
	"encoding/binary"
	"errors"
	"strings"
)

type question struct {
	name        string
	kind, class uint16
}
type record struct {
	name        string
	kind, class uint16
	ttl         uint32
	data        []byte
}
type message struct {
	id, flags                      uint16
	questions                      []question
	answers, authority, additional []record
}

var malformed = errors.New("malformed DNS message")

func nameAt(b []byte, start int) (string, int, error) {
	pos, next := start, -1
	labels := make([]string, 0, 4)
	seen := make(map[int]bool)
	size := 0
	for steps := 0; steps < 128; steps++ {
		if pos >= len(b) || seen[pos] {
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
			if next < 0 {
				next = pos
			}
			pos = target
			continue
		}
		if n&0xc0 != 0 || n > 63 {
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
		if size > 254 {
			return "", 0, malformed
		}
		label := string(b[pos : pos+n])
		for _, c := range []byte(label) {
			if c < 33 || c > 126 || c == '.' {
				return "", 0, malformed
			}
		}
		labels = append(labels, label)
		pos += n
	}
	return "", 0, malformed
}

func parse(b []byte, max int) (message, error) {
	m := message{}
	if len(b) < 12 || len(b) > max {
		return m, malformed
	}
	m.id = binary.BigEndian.Uint16(b)
	m.flags = binary.BigEndian.Uint16(b[2:])
	counts := [4]int{}
	total := 0
	for i := range counts {
		counts[i] = int(binary.BigEndian.Uint16(b[4+2*i:]))
		total += counts[i]
	}
	if total > 256 {
		return m, malformed
	}
	off := 12
	for i := 0; i < counts[0]; i++ {
		n, next, e := nameAt(b, off)
		if e != nil || next+4 > len(b) {
			return m, malformed
		}
		m.questions = append(m.questions, question{n, binary.BigEndian.Uint16(b[next:]), binary.BigEndian.Uint16(b[next+2:])})
		off = next + 4
	}
	sections := []*[]record{&m.answers, &m.authority, &m.additional}
	for s, out := range sections {
		for i := 0; i < counts[s+1]; i++ {
			n, next, e := nameAt(b, off)
			if e != nil || next+10 > len(b) {
				return m, malformed
			}
			length := int(binary.BigEndian.Uint16(b[next+8:]))
			end := next + 10 + length
			if end > len(b) {
				return m, malformed
			}
			*out = append(*out, record{n, binary.BigEndian.Uint16(b[next:]), binary.BigEndian.Uint16(b[next+2:]), binary.BigEndian.Uint32(b[next+4:]), b[next+10 : end]})
			off = end
		}
	}
	if off != len(b) {
		return m, malformed
	}
	return m, nil
}

func appendName(b []byte, name string) []byte {
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	return append(b, 0)
}

func response(req []byte, q question, address []byte, ttl uint32) []byte {
	b := make([]byte, 12)
	if len(req) >= 2 {
		copy(b, req[:2])
	}
	flags := uint16(0x8080)
	if len(req) >= 4 {
		flags |= binary.BigEndian.Uint16(req[2:]) & 0x0100
	}
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = appendName(b, q.name)
	b = binary.BigEndian.AppendUint16(b, q.kind)
	b = binary.BigEndian.AppendUint16(b, q.class)
	if address != nil {
		binary.BigEndian.PutUint16(b[6:], 1)
		b = append(b, 0xc0, 0x0c)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = append(b, address...)
	}
	return b
}

// Rebuild selected queries using the canonical question spelling. Passing case
// variants or client sections to the allocator would widen its cache namespace.
func canonicalQuery(req []byte, q question) []byte {
	b := make([]byte, 12)
	copy(b, req[:2])
	binary.BigEndian.PutUint16(b[2:], binary.BigEndian.Uint16(req[2:])&0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = appendName(b, q.name)
	b = binary.BigEndian.AppendUint16(b, q.kind)
	return binary.BigEndian.AppendUint16(b, q.class)
}

func failure(req []byte, q *question) []byte {
	var b []byte
	if q != nil {
		b = response(req, *q, nil, 0)
	} else {
		b = make([]byte, 12)
		if len(req) >= 2 {
			copy(b, req[:2])
		}
		b[2] = 0x80
	}
	b[3] = (b[3] & 0xf0) | 2
	return b
}
