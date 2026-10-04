#!/usr/bin/env python3
"""Native Netwatch failure proof against the localhost disposable CHR only."""
import json
import time
from chr_dataplane import ROOT, rest, gateway, request, assert_success

COMMENTS = {'mikrocentauri:lab:route:fakeip', 'mikrocentauri:lab:nat:dns-tcp', 'mikrocentauri:lab:nat:dns-udp'}

def flags():
    rows = rest('GET', 'ip/route') + rest('GET', 'ip/firewall/nat')
    result = {row['comment']: row.get('disabled', 'false') == 'true' for row in rows if row.get('comment') in COMMENTS}
    assert len(result) == 3, result
    return result

def wait_state(disabled, start, timeout=15):
    while time.monotonic() - start < timeout:
        state = flags()
        watches = rest('GET', 'tool/netwatch')
        watch = next(w for w in watches if w.get('comment') == 'mikrocentauri:lab:netwatch:readiness')
        if all(v == disabled for v in state.values()) and watch['status'] == ('down' if disabled else 'up'):
            # Allow the measured asynchronous dataplane update after REST state changes.
            time.sleep(1)
            return {'observed_ms': round((time.monotonic()-start)*1000), 'flags': state, 'netwatch': watch['status']}
        time.sleep(.1)
    raise AssertionError('Watchdog transition timeout')

def down_results(saved):
    direct = request('unselected.test', path='/direct-during-failure')
    fresh = request('selected.test', path='/fresh-dns-during-failure')
    cached = request(saved, path='/cached-fakeip-during-failure')
    assert_success(direct, '10.77.0.1')
    assert_success(fresh, '10.77.0.1')
    assert fresh['resolved_ipv4'] == '10.77.0.20', fresh
    assert cached.get('error'), 'Cached FakeIP unexpectedly reached a target'
    return {'direct': direct, 'fresh_selected': fresh, 'cached_fakeip': cached}

def run():
    assert gateway()['ready']
    selected = request('selected.test')
    assert_success(selected, '10.77.0.10')
    saved = selected['resolved_ipv4']
    assert saved.startswith('198.18.')
    before = {'filter': rest('GET', 'ip/firewall/filter'), 'mangle': rest('GET','ip/firewall/mangle')}
    started = time.monotonic()
    gateway('post', '/control/stop')
    engine_down = wait_state(True, started)
    engine_down['clients'] = down_results(saved)
    started = time.monotonic()
    assert gateway('post', '/control/start')['ready']
    engine_up = wait_state(False, started)
    recovered = request('selected.test'); assert_success(recovered, '10.77.0.10')
    engine_up['client'] = recovered
    container = next(c for c in rest('GET', 'container') if c.get('running') == 'true' and c['name'].startswith('mc-gateway'))
    started = time.monotonic()
    rest('POST', 'container/stop', {'numbers': container['.id']})
    container_down = wait_state(True, started)
    container_down['clients'] = down_results(saved)
    started = time.monotonic()
    rest('POST', 'container/start', {'numbers': container['.id']})
    container_up = wait_state(False, started)
    recovered = request('selected.test'); assert_success(recovered, '10.77.0.10')
    container_up['client'] = recovered
    after = {'filter': rest('GET', 'ip/firewall/filter'), 'mangle': rest('GET','ip/firewall/mangle')}
    assert before == after, 'Unrelated filter/mangle modified'
    return {'engine_stop': engine_down, 'engine_restart': engine_up, 'container_stop': container_down,
            'container_restart': container_up, 'unrelated_filter_mangle_unchanged': True,
            'acceptance': 'FAIL: cached FakeIP cannot recover DIRECT while engine is unavailable'}

if __name__ == '__main__':
    report = run()
    (ROOT / '.cache/dataplane/failure-results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
