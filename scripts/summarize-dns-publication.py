#!/usr/bin/env python3
"""Extract public fixture DNS witnesses from classic Ethernet PCAP; UDP53 only."""
import argparse
import collections
import ipaddress
import json
import pathlib
import struct


def name(packet, start):
    labels = []
    seen = set()
    end = None
    pos = start
    for _ in range(128):
        if pos in seen or pos >= len(packet):
            raise ValueError('Invalid DNS name')
        seen.add(pos)
        size = packet[pos]
        if size & 0xc0 == 0xc0:
            if pos+1 >= len(packet):
                raise ValueError('Truncated pointer')
            end = end or pos+2
            pos = ((size & 63) << 8) | packet[pos+1]
            continue
        pos += 1
        if size == 0:
            return '.'.join(labels).lower(), end or pos
        if size > 63 or pos+size > len(packet):
            raise ValueError('Invalid label')
        labels.append(packet[pos:pos+size].decode('ascii'))
        pos += size
    raise ValueError('DNS name jump limit')


def summarize(path):
    data = pathlib.Path(path).read_bytes()
    if len(data)<24 or data[:4] != b'\xd4\xc3\xb2\xa1' or struct.unpack_from('<I',data,20)[0]!=1:
        raise ValueError('Classic Ethernet PCAP required')
    offset = 24
    rows = []
    while offset+16 <= len(data):
        sec, usec, length, _ = struct.unpack_from('<IIII', data, offset)
        offset += 16
        frame = data[offset:offset+length]
        offset += length
        if len(frame)!=length:
            raise ValueError('Truncated capture')
        if len(frame)<42 or frame[12:14]!=b'\x08\x00' or frame[23]!=17:
            continue
        if struct.unpack_from('!H',frame,20)[0]&0x1fff:
            continue
        start = 14+(frame[14]&15)*4
        if len(frame)<start+8:
            continue
        source_port, _, udp_length = struct.unpack_from('!HHH',frame,start)
        if source_port!=53:
            continue
        packet = frame[start+8:start+udp_length]
        if len(packet)<12:
            continue
        ident, flags, questions, answers, _, _ = struct.unpack_from('!6H',packet)
        if not flags&0x8000 or questions!=1:
            continue
        try:
            domain, end = name(packet,12)
            if domain not in ('selected.test','second.test','third.test'):
                continue
            position = end+4
            addresses = []
            for _ in range(answers):
                _, position = name(packet,position)
                kind, cls, ttl, size = struct.unpack_from('!HHIH',packet,position)
                position += 10
                value = packet[position:position+size]
                if len(value)!=size:
                    raise ValueError('Truncated answer')
                if kind==1 and cls==1 and size==4:
                    addresses.append({'address':str(ipaddress.IPv4Address(value)), 'ttl':ttl})
                position += size
        except (ValueError, UnicodeError, struct.error):
            continue
        rows.append({'time_utc_epoch':sec+usec/1000000,'id':ident,'domain':domain,
                     'rcode':flags&15,'answer_count':answers,'a':addresses})
    failures = [r for r in rows if r['rcode']==2]
    assert all(r['answer_count']==0 and not r['a'] for r in failures)
    return {'file':pathlib.Path(path).name,'response_counts':dict(collections.Counter(f"{r['domain']}:rcode={r['rcode']}" for r in rows)),
            'servfail_without_alias':failures,'scope':'Public fixture UDP DNS response witnesses; not loss or timing bounds'}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('pcap')
    p.add_argument('--out', required=True)
    a = p.parse_args()
    pathlib.Path(a.out).write_text(json.dumps(summarize(a.pcap),indent=2)+'\n')
