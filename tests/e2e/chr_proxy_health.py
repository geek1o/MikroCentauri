#!/usr/bin/env python3
"""Run down/up after stopping/restarting VLESS in the isolated server VM console."""
import argparse
import json
import urllib.request
from chr_cached_fallback import wait_state, clients
from chr_dataplane import ROOT, gateway

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('down', 'up'))
    args = parser.parse_args()
    up = args.action == 'up'
    result = wait_state(up)
    if up:
        health = gateway()
        assert health['ready'] and health['consecutive_successes'] == 3
    else:
        req = urllib.request.Request('http://127.0.0.1:19010/request',
            data=json.dumps({'domain': '172.30.0.2', 'port': 9099, 'path': '/'}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=16) as response:
            raw = json.load(response)
        assert raw['error'] == 'target returned HTTP 503', raw
        health = json.loads(raw['body'])
        assert health['local_ready'] and not health['ready'] and health['consecutive_failures'] == 2
    result['health'] = health
    result['clients'] = clients('198.18.0.2', '10.77.0.10' if up else '10.77.0.1')
    path = ROOT/'.cache/dataplane/proxy-outage-results.json'
    report = json.loads(path.read_text()) if path.exists() else {}
    report['recovery' if up else 'outage'] = result
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(result, indent=2))
