#!/usr/bin/env python3
"""Bind completed backend acceptance UDP workloads to exact-run WAN packets."""
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
    assert report.get('completed'), 'Native backend acceptance incomplete'
    run_id = report['run_id']
    witnesses = []
    for path, workload in workloads(report):
        marker = workload['udp']['capture_marker']
        match = re.fullmatch(r'phase4-([0-9]+)-([0-9]+)-([a-z]+\.test)-([0-9]+)', marker)
        assert match and match[1] == run_id, marker
        peer = workload['expected_peer']
        assert peer in ('10.77.0.10', '10.77.0.1'), workload
        expected = ('tcp', '10.77.0.10', 8443) if peer == '10.77.0.10' else ('udp', '10.77.0.20', 9000)
        hits = [packet for packet in wan['api_udp_marker']
                if packet['marker'] == marker
                and (packet['protocol'], packet['destination'], packet['destination_port']) == expected
                and packet['source'] == '10.77.0.1']
        assert hits, {'missing_forwarding_witness': marker, 'expected': expected}
        witnesses.append({'stage': '.'.join(path), 'marker': marker,
                          'expected_forward_path': expected,
                          'matching_forward_packets': len(hits), 'first_packet': hits[0]})
    assert witnesses, 'No accepted UDP workloads'
    assert len({w['marker'] for w in witnesses}) == len(witnesses), 'Duplicate workloads'
    return {'scope': 'WAN packets for exact-run UDP markers; no stream reconstruction, reboot or loss bounds',
            'run_id': run_id, 'wan_sha256': wan['sha256'], 'workloads': witnesses}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results', required=True)
    p.add_argument('--capture-summary', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    report = json.loads(pathlib.Path(a.results).read_text())
    captures = json.loads(pathlib.Path(a.capture_summary).read_text())
    wan = next(c for c in captures if c['file'].endswith('wan.pcap'))
    result = verify(report, wan)
    pathlib.Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
    print(f"Verified {len(result['workloads'])} backend UDP forwarding witnesses")
