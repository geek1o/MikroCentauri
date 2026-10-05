#!/usr/bin/env python3
"""Link accepted phase8 UDP workloads to forwarding markers in the WAN capture."""
import argparse
import json
import pathlib
import re


def workloads(value, path=()):
    if isinstance(value, dict):
        if 'expected_peer' in value and 'capture_marker' in value.get('udp', {}):
            yield path, value
        for key, item in value.items():
            yield from workloads(item, path + (key,))


def verify(report, wan):
    assert report.get('completed'), 'Native acceptance incomplete'
    witnesses = []
    for path, workload in workloads(report):
        marker = workload['udp']['capture_marker']
        match = re.fullmatch(r'phase8-(\d+)-([a-z]+\.test)-(\d+)', marker)
        assert match, marker
        proxy = workload['expected_peer'] == '10.77.0.10'
        assert proxy or workload['expected_peer'] == '10.77.0.1', workload
        expected = ('tcp', '10.77.0.10', 8443) if proxy else ('udp', '10.77.0.20', 9000)
        hits = [packet for packet in wan['activation_udp_marker']
                if (packet['revision'], packet['domain'], packet['sequence']) ==
                (int(match[1]), match[2], int(match[3]))
                and (packet['protocol'], packet['destination'], packet['destination_port']) == expected
                and packet['source'] == '10.77.0.1']
        assert hits, {'missing_forwarding_witness': marker, 'expected': expected}
        witnesses.append({'stage': '.'.join(path), 'marker': marker,
                          'expected_forward_path': expected,
                          'matching_forward_packets': len(hits), 'first_packet': hits[0]})
    assert witnesses, 'No accepted UDP workloads'
    assert len({w['marker'] for w in witnesses}) == len(witnesses), 'Duplicate markers'
    return {'scope': 'WAN packet witnesses for accepted UDP workloads; no stream reconstruction, transaction or loss bounds',
            'wan_sha256': wan['sha256'], 'workloads': witnesses}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', required=True)
    parser.add_argument('--capture-summary', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    report = json.loads(pathlib.Path(args.results).read_text())
    captures = json.loads(pathlib.Path(args.capture_summary).read_text())
    wan = next(c for c in captures if c['file'].endswith('-wan.pcap'))
    result = verify(report, wan)
    pathlib.Path(args.out).write_text(json.dumps(result, indent=2) + '\n')
    print(f"Verified {len(result['workloads'])} marked UDP workloads")
