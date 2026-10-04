#!/usr/bin/env python3
"""Explicit disposable-CHR tests. Requires the isolated lab; never targets a real router."""
import base64
import json
import pathlib
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = 'http://127.0.0.1:18080/rest/'
# Public disposable lab fixture. Never reuse this account/password on a real router.
AUTH = 'Basic ' + base64.b64encode(b'mc-lab:DisposableLabOnly-2026').decode()


def rest(method, path, data=None):
    request = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Authorization': AUTH, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode()) from None


def request(domain, source='', udp=False, path='/test'):
    body = {'domain': domain, 'source': source, 'path': path}
    endpoint = 'udp' if udp else 'request'
    req = urllib.request.Request(f'http://127.0.0.1:19010/{endpoint}',
        data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=16) as response:
        return json.load(response)


def gateway(method='get', path='/'):
    rows = rest('POST', 'tool/fetch', {'url': 'http://172.30.0.2:9099' + path,
        'http-method': method, 'output': 'user'})
    return next((json.loads(row['data']) for row in rows if row.get('data')), None)


def set_owned(enabled):
    for path, comments in [('ip/route', ['mikrocentauri:lab:route:fakeip']),
        ('ip/firewall/nat', ['mikrocentauri:lab:nat:dns-tcp', 'mikrocentauri:lab:nat:dns-udp'])]:
        rows = rest('GET', path)
        for comment in comments:
            matches = [row for row in rows if row.get('comment') == comment]
            if len(matches) != 1:
                raise RuntimeError('Missing or duplicate lab ownership: ' + comment)
            rest('PATCH', path + '/' + matches[0]['.id'], {'disabled': str(not enabled).lower()})
    # REST completion precedes the observed firewall dataplane update in this CHR.
    time.sleep(1)


def assert_success(result, egress=None):
    assert not result.get('error'), result
    if egress:
        assert result.get('proxy_seen_ip') == egress, result


def baseline():
    resource = rest('GET', 'system/resource')
    assert resource['platform'] == 'MikroTik' and resource['board-name'].startswith('CHR '), 'Disposable CHR required'
    set_owned(False)
    rest('POST', 'ip/dns/cache/flush', {})
    direct = request('unselected.test', path='/direct-baseline')
    assert_success(direct, '10.77.0.1')
    assert_success(request('selected.test', path='/selected-without-gateway'), '10.77.0.1')
    return {'routeros': resource['version'], 'direct': direct}


def transparent():
    assert gateway()['ready']
    set_owned(True)
    selected = request('selected.test', path='/hybrid-selected')
    direct = request('unselected.test', path='/hybrid-direct')
    assert_success(selected, '10.77.0.10')
    assert selected['resolved_ipv4'].startswith('198.18.')
    assert_success(direct, '10.77.0.1')
    assert direct['resolved_ipv4'] == '10.77.0.20'
    udp = request('selected.test', udp=True)
    assert_success(udp)
    return {'selected': selected, 'direct': direct, 'udp': udp}


if __name__ == '__main__':
    report = {'baseline': baseline(), 'hybrid': transparent()}
    path = ROOT / '.cache/dataplane/basic-results.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
