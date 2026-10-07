#!/usr/bin/env python3
"""Bind native App UDP acceptance and image changes to exact-run LAN/WAN packets."""
import argparse, json, pathlib, re


def workloads(value, path=()):
    if isinstance(value, dict):
        if 'expected_peer' in value and 'capture_marker' in value.get('udp', {}):
            yield path, value
        for key, item in value.items():
            yield from workloads(item, path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from workloads(item, path + (str(index),))


def verify(report, captures):
    assert report.get('accepted') and report.get('completed'), 'Native App acceptance incomplete'
    wan = next(c for c in captures if c['file'] == 'wan.pcap')
    lan = next(c for c in captures if c['file'] == 'lan.pcap')
    witnesses = []
    for path, workload in workloads(report):
        marker = workload['udp']['capture_marker']
        match = re.fullmatch(r'phase4-([0-9]+)-1-([a-z]+\.test)-([0-9]+)', marker)
        assert match and match[1] == report['run_id'], 'Wrong acceptance run'
        peer = workload['expected_peer']
        assert peer in ('10.77.0.10', '10.77.0.1')
        expected = ('tcp', '10.77.0.10', 8443) if peer == '10.77.0.10' else ('udp', '10.77.0.20', 9000)
        outbound = [p for p in wan['api_udp_marker'] if p['marker'] == marker and p['source'] == '10.77.0.1'
                    and (p['protocol'], p['destination'], p['destination_port']) == expected]
        ingress = [p for p in lan['api_udp_marker'] if p['marker'] == marker and p['protocol'] == 'udp'
                   and p['source'] == '192.168.88.10' and p['destination'] == workload['udp']['resolved_ipv4']
                   and p['destination_port'] == 9000]
        assert outbound and ingress, 'Missing actual forwarding witness for ' + marker
        witnesses.append({'stage': '.'.join(path), 'marker': marker, 'expected_forward_path': expected,
                          'lan_packet': ingress[0], 'wan_packet': outbound[0]})
    assert len(witnesses) == 4, 'Expected selected/direct and two image replacement UDP witnesses'
    assert len({w['marker'] for w in witnesses}) == 4, 'Markers must be unique'
    return {'run_id': report['run_id'], 'scope': 'exact-run UDP ingress/forwarding witnesses; TCP/H3 peers in native report',
            'lan_sha256': lan['sha256'], 'wan_sha256': wan['sha256'], 'workloads': witnesses}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', required=True, type=pathlib.Path)
    parser.add_argument('--captures', required=True, type=pathlib.Path)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    result = verify(json.loads(args.results.read_text()), json.loads(args.captures.read_text()))
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print('Verified 4 native App UDP forwarding witnesses, including image replacement')
