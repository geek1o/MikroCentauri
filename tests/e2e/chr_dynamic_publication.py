#!/usr/bin/env python3
"""Three-domain publication/fail-open fixture, only localhost disposable CHR."""
import json
import time
from chr_dataplane import ROOT, rest, request, assert_success
from chr_protocols import quic

COMMENTS = {'mikrocentauri:lab:route:fakeip', 'mikrocentauri:lab:nat:dns-tcp',
            'mikrocentauri:lab:nat:dns-udp', 'mikrocentauri:lab:nat:dynamic-jump'}


def wait(up, timeout=45):
    started = time.monotonic()
    while time.monotonic()-started < timeout:
        rows = rest('GET', 'ip/route') + rest('GET', 'ip/firewall/nat')
        flags = {r['comment']: r.get('disabled', 'false') == 'true'
                 for r in rows if r.get('comment') in COMMENTS}
        expected = {c: (up if c.endswith('dynamic-jump') else not up) for c in COMMENTS}
        watch = next(r for r in rest('GET', 'tool/netwatch')
                     if r.get('comment') == 'mikrocentauri:lab:netwatch:readiness')
        if flags == expected and watch['status'] == ('up' if up else 'down'):
            time.sleep(1)
            return {'observed_ms_from_poll': round((time.monotonic()-started)*1000), 'flags': flags}
        time.sleep(.2)
    raise AssertionError('Native transition timeout')


def maps():
    return [r for r in rest('GET', 'ip/firewall/nat') if r.get('chain') == 'mc-dynamic-backup']


def traffic(name, alias, peer):
    tcp = request(alias, path='/dynamic-cached-'+name)
    udp = request(alias, udp=True)
    h3 = quic(name, alias)
    assert_success(tcp, peer)
    assert_success(udp)
    assert h3['remote_ip'] == peer, h3
    return {'tcp': tcp, 'udp': udp, 'http3': h3}


def publish(name):
    attempts = []
    for _ in range(5):
        rest('POST', 'ip/dns/cache/flush', {})
        r = request(name, path='/dynamic-publication-'+name)
        attempts.append(r)
        if not r.get('error'):
            assert_success(r, '10.77.0.10')
            return r, attempts
        # Preserve failed DNS responses as evidence; never retry a published
        # address with a broken dataplane as if it were a publication success.
        assert not r.get('resolved_ipv4'), r
        time.sleep(.5)
    raise AssertionError(attempts)


if __name__ == '__main__':
    assert rest('GET', 'system/resource')['board-name'].startswith('CHR ')
    result = {'initial': wait(True), 'published': {}, 'saved_aliases': {}}
    for name in ('selected.test', 'second.test'):
        r, attempts = publish(name)
        assert_success(r, '10.77.0.10')
        alias = r['resolved_ipv4']
        assert alias.startswith('198.18.')
        owned = [m for m in maps() if m['dst-address'] == alias]
        assert len(owned) == 1 and owned[0]['to-addresses'] == '10.77.0.20'
        assert owned[0].get('disabled', 'false') == 'false'
        result['published'][name] = {'request': r, 'attempts': attempts, 'router_map': owned[0]}
        result['saved_aliases'][name] = alias
    assert len(set(result['saved_aliases'].values())) == 2
    assert not [m for m in maps() if m['dst-address'] not in result['saved_aliases'].values()], 'Fresh fixture required'
    blocked = None
    try:
        # Reject the actual transport, including existing HTTP keep-alive sockets.
        # A service access-list change alone does not terminate established sockets.
        blocked = rest('PUT', 'ip/firewall/filter', {'chain': 'input', 'action': 'reject',
            'reject-with': 'tcp-reset', 'src-address': '172.30.0.2',
            'dst-address': '172.30.0.1', 'protocol': 'tcp', 'dst-port': '80',
            'comment': 'disposable-dynamic-control-block'})
        rest('POST', 'ip/dns/cache/flush', {})
        failure = request('third.test', path='/must-not-publish')
        assert failure.get('error') and not failure.get('resolved_ipv4'), failure
        assert len(maps()) == 2, 'Unverified third map created'
        result['control_link_failure'] = failure
    finally:
        if blocked is not None:
            rest('DELETE', 'ip/firewall/filter/'+blocked['.id'])
    wait(True)
    rest('POST', 'ip/dns/cache/flush', {})
    third, attempts = publish('third.test')
    assert_success(third, '10.77.0.10')
    result['saved_aliases']['third.test'] = third['resolved_ipv4']
    assert len(maps()) == 3
    result['third_after_recovery'] = third
    result['third_publication_attempts'] = attempts
    result['healthy'] = {n: traffic(n,a,'10.77.0.10') for n,a in result['saved_aliases'].items()}
    container = next(c for c in rest('GET', 'container') if c['name'] == 'mc-gateway-phase3')
    rest('POST', 'container/stop', {'numbers': container['.id']})
    result['container_down'] = wait(False)
    result['cached_direct'] = {n: traffic(n,a,'10.77.0.1') for n,a in result['saved_aliases'].items()}
    rest('POST', 'container/start', {'numbers': container['.id']})
    result['container_up'] = wait(True)
    result['cached_proxy_restored'] = {n: traffic(n,a,'10.77.0.10') for n,a in result['saved_aliases'].items()}
    for n,a in result['saved_aliases'].items():
        assert request(n)['resolved_ipv4'] == a, 'Alias changed on restart'
    result['unselected'] = request('unselected.test')
    assert_success(result['unselected'], '10.77.0.1')
    result['scope'] = 'Three pinned IPv4 domains, new connections; no churn/GC/IPv6/capacity claim'
    (ROOT/'.cache/dataplane/dynamic-publication-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
