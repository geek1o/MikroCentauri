#!/usr/bin/env python3
"""Static cached-IP fixture; localhost disposable CHR only, not general acceptance."""
import json
import time
from chr_dataplane import ROOT, rest, request, gateway, assert_success
from chr_protocols import quic

COMMENTS = {'mikrocentauri:lab:route:fakeip', 'mikrocentauri:lab:nat:dns-tcp',
            'mikrocentauri:lab:nat:dns-udp', 'mikrocentauri:lab:nat:cached-selected'}


def configuration(path):
    return [{k: v for k, v in row.items() if k not in ('bytes', 'packets')}
            for row in rest('GET', path) if row.get('dynamic') != 'true']


def wait_state(up, started=None, timeout=30):
    started = started or time.monotonic()
    while time.monotonic() - started < timeout:
        rows = rest('GET', 'ip/route') + rest('GET', 'ip/firewall/nat')
        flags = {r['comment']: r.get('disabled', 'false') == 'true'
                 for r in rows if r.get('comment') in COMMENTS}
        watch = next(w for w in rest('GET', 'tool/netwatch')
                     if w.get('comment') == 'mikrocentauri:lab:netwatch:readiness')
        expected = {c: (up if c.endswith('cached-selected') else not up) for c in COMMENTS}
        if flags == expected and watch['status'] == ('up' if up else 'down'):
            time.sleep(1)  # observed CHR firewall application delay
            return {'observed_ms': round((time.monotonic()-started)*1000),
                    'flags': flags, 'netwatch': watch['status']}
        time.sleep(.2)
    raise AssertionError('Native watchdog transition timeout')


def clients(saved, peer):
    tcp = request(saved, path='/cached-phase2')
    udp = request(saved, udp=True)
    http3 = quic('selected.test', saved)
    assert_success(tcp, peer)
    assert_success(udp)
    assert http3['remote_ip'] == peer, http3
    fresh = request('selected.test', path='/fresh-phase2')
    direct = request('unselected.test')
    assert_success(fresh, peer)
    assert_success(direct, '10.77.0.1')
    return {'cached_tcp': tcp, 'cached_udp': udp, 'cached_http3': http3,
            'fresh_selected': fresh, 'unselected': direct}


def run():
    resource = rest('GET', 'system/resource')
    assert resource['board-name'].startswith('CHR '), 'Disposable CHR required'
    wait_state(True)
    saved = request('selected.test')['resolved_ipv4']
    assert saved == '198.18.0.2', 'This experiment has exactly one static mapping'
    before = {p: configuration(p) for p in ('ip/firewall/filter', 'ip/firewall/mangle')}
    result = {'routeros': resource['version'], 'healthy': clients(saved, '10.77.0.10')}
    started = time.monotonic()
    gateway('post', '/control/stop')
    result['engine_stop'] = wait_state(False, started)
    result['engine_stop']['clients'] = clients(saved, '10.77.0.1')
    started = time.monotonic()
    assert gateway('post', '/control/start') == {'starting': True}
    result['engine_restart'] = wait_state(True, started)
    result['engine_restart']['clients'] = clients(saved, '10.77.0.10')
    container = next(c for c in rest('GET', 'container') if c['name'] == 'mc-gateway-phase2')
    started = time.monotonic()
    rest('POST', 'container/stop', {'numbers': container['.id']})
    result['container_stop'] = wait_state(False, started)
    result['container_stop']['clients'] = clients(saved, '10.77.0.1')
    started = time.monotonic()
    rest('POST', 'container/start', {'numbers': container['.id']})
    result['container_restart'] = wait_state(True, started)
    result['container_restart']['clients'] = clients(saved, '10.77.0.10')
    after = {p: configuration(p) for p in before}
    assert before == after, 'Filter/mangle changed unexpectedly'
    result['unrelated_filter_mangle_unchanged'] = True
    result['scope'] = 'PASS: one pinned mapping, new connections; dynamic FakeIP gate remains open'
    return result


if __name__ == '__main__':
    report = run()
    (ROOT / '.cache/dataplane/cached-fallback-results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
