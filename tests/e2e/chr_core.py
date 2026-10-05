#!/usr/bin/env python3
"""Product Phase 3 core acceptance on the disposable localhost CHR only.

Requires lab/coregateway, separate 198.19/16 state, and the running client/server
VMs. Keeps old namespace stores and containers intact. Capture witnesses are
verified separately; an echoed UDP payload alone does not prove egress.
"""
import argparse
import base64
import itertools
import json
import time
import urllib.request

from chr_dataplane import ROOT, rest, request, assert_success
from chr_dynamic_publication import wait, maps
from chr_binding_policy import workload
from chr_protocols import quic

sequence = itertools.count(1)


def core(path='/status', body=None):
    params = {'url': 'http://172.30.0.2:9099' + path,
              'http-method': 'get' if body is None else 'post', 'output': 'user'}
    if body is not None:
        params.update({'http-data': json.dumps(body),
                       'http-header-field': 'Content-Type: application/json'})
    rows = rest('POST', 'tool/fetch', params)
    return next(json.loads(r['data']) for r in rows if r.get('data'))


def aliases():
    state = settled()['status']
    return {b['domain']: b['alias'] for b in state['admission']['bindings']}


def settled():
    native = wait(True)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        state = core()
        if state['ready'] and state['admission']['admitted']:
            return {'native': native, 'status': state}
        time.sleep(.2)
    raise AssertionError('Core readiness did not settle')


def apply(revision, active, fault=None):
    body = {'revision': revision, 'active': active}
    if fault:
        body['fault'] = fault
    return core('/control/namespace', body)


def matrix(bindings, active, revision, source='', expected=None):
    result = {}
    for name, alias in bindings.items():
        peer = expected or ('10.77.0.10' if name in active else '10.77.0.1')
        http = workload('unselected.test', source=source, domain=name, address=alias)
        assert_success(http, peer)
        h3 = quic('unselected.test', alias, source)
        assert h3['remote_ip'] == peer, h3
        marker = f'phase8-{revision}-{name}-{next(sequence)}'
        req = urllib.request.Request('http://127.0.0.1:19010/udp',
            data=json.dumps({'domain': name, 'address': alias, 'skip_dns': True,
                             'source': source, 'payload': marker}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=16) as response:
            udp = json.load(response)
        assert_success(udp)
        udp['capture_marker'] = marker
        result[name] = {'expected_peer': peer, 'http_foreign_host': http,
                        'http3_foreign_sni': h3, 'udp': udp}
    return result


def read_policy(root):
    # This fixed public admin fixture reads only the new container's private
    # namespace journal. The running core retains its restricted mc-lab account.
    assert root in ('pcie2/mc-core-v3', 'pcie2/mc-core-v3-final'), root
    req = urllib.request.Request('http://127.0.0.1:18080/rest/file/read',
        data=json.dumps({'file': root + '/data/core-v3/namespace/namespace.json',
                         'offset': '0', 'chunk-size': '32768'}).encode(),
        headers={'Content-Type': 'application/json',
                 'Authorization': 'Basic ' + base64.b64encode(b'admin:').decode()})
    with urllib.request.urlopen(req, timeout=30) as response:
        rows = json.load(response)
    if isinstance(rows, dict):
        rows = [rows]
    raw = ''.join(r['data'] for r in rows if 'data' in r)
    value = json.loads(raw)
    return {k: v for k, v in value.items() if k in ('revision', 'known', 'active', 'pending')}


def run(args):
    report = {'scope': 'Pinned CHR 7.24.5 x86_64; core v2; new connections; process death, not power loss'}
    damaged = None
    try:
        fixture = urllib.request.Request('http://127.0.0.1:19020/dns-fixture',
            data=json.dumps({'target': '10.77.0.20', 'ttl': 30, 'all_ttl': 30, 'fail': False}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(fixture, timeout=5) as response:
            report['dns_fixture'] = json.load(response)
        resource = rest('GET', 'system/resource')
        assert resource['board-name'].startswith('CHR ') and resource['version'].startswith('7.24.5')
        container = next(c for c in rest('GET', 'container') if c['name'] == args.container)
        report['initial'] = settled()
        original = aliases()
        assert {'selected.test', 'second.test', 'third.test'} <= original.keys() and all(a.startswith('198.19.') for a in original.values()), original
        current = core()['namespace']
        base = current['revision']
        report['initial_bindings'] = original
        report['initial_cached'] = matrix(original, current['active'], base)

        retired = apply(base, ['selected.test', 'third.test'])
        report['retired'] = {'policy': retired, 'up': settled()}
        assert aliases() == original
        rest('POST', 'ip/dns/cache/flush', {})
        dns = request('SeCoNd.TeSt.', path='/core-retired-dns')
        assert_success(dns, '10.77.0.1')
        assert dns['resolved_ipv4'] == '10.77.0.20', dns
        report['retired_new_dns'] = dns
        report['retired_cached'] = matrix(original, retired['active'], retired['revision'])
        report['source_overrides'] = {
            source: matrix(original, retired['active'], retired['revision'], source, peer)
            for source, peer in [('192.168.88.20', '10.77.0.10'), ('192.168.88.30', '10.77.0.1')]}

        expanded = apply(retired['revision'], retired['active'] + ['fourth.test'])
        report['expanded'] = {'policy': expanded, 'up': settled()}
        bindings = aliases()
        assert all(bindings[n] == a for n, a in original.items()) and 'fourth.test' in bindings and len(set(bindings.values())) == len(bindings)
        report['expanded_bindings'] = bindings
        rest('POST', 'ip/dns/cache/flush', {})
        new = request('fourth.test', path='/core-new-domain')
        assert_success(new, '10.77.0.10')
        assert new['resolved_ipv4'] == bindings['fourth.test']
        report['addition_dns'] = new

        inactive = apply(expanded['revision'], [])
        report['all_retired'] = {'policy': inactive, 'up': settled(),
                                'cached': matrix(bindings, [], inactive['revision'])}
        assert aliases() == bindings
        restored = apply(inactive['revision'], inactive['known'])
        report['reactivated'] = {'policy': restored, 'up': settled(),
                                'cached': matrix(bindings, restored['active'], restored['revision'])}
        assert aliases() == bindings
        before = core()
        try:
            apply(base, ['selected.test'])
            raise AssertionError('Stale revision accepted')
        except RuntimeError as error:
            report['stale_rejected'] = str(error)
        assert core()['namespace'] == before['namespace'] and core()['ready']

        rest('POST', 'container/stop', {'numbers': container['.id']})
        report['stopped'] = wait(False)
        report['stopped_cached'] = matrix(bindings, [], restored['revision'])
        rest('POST', 'container/start', {'numbers': container['.id']})
        report['reopened'] = settled()
        assert aliases() == bindings and core()['namespace'] == restored

        damaged = next(m for m in maps() if m['dst-address'] == bindings['third.test'])
        rest('PATCH', 'ip/firewall/nat/' + damaged['.id'], {'disabled': 'true'})
        try:
            apply(restored['revision'], ['selected.test', 'fourth.test'])
            raise AssertionError('Damaged native binding admitted')
        except RuntimeError as error:
            report['damaged_backend_rejected'] = str(error)
        pending = core()['namespace']
        assert pending['pending']['revision'] == restored['revision'] + 1 and not core()['ready']
        report['pending'] = pending
        report['pending_down'] = wait(False)
        rest('PATCH', 'ip/firewall/nat/' + damaged['.id'], {'disabled': 'false'})
        damaged = None
        report['pending_cached_direct'] = matrix(bindings, [], pending['pending']['revision'])
        recovered = core('/control/recover', {})
        report['repaired_recovery'] = {'policy': recovered, 'up': settled()}
        assert aliases() == bindings and 'pending' not in recovered

        for boundary, addition in [('after-verify', 'fifth.test'), ('before-release', 'sixth.test')]:
            previous = core()['namespace']
            desired = previous['active'] + [addition] if addition not in previous['active'] else [n for n in previous['active'] if n != addition]
            try:
                apply(previous['revision'], desired, boundary)
                raise AssertionError('Injected death returned normally')
            except RuntimeError:
                pass
            down = wait(False)
            disk = read_policy(container['root-dir'].lstrip('/'))
            if boundary == 'after-verify':
                assert disk['revision'] == previous['revision'] and disk['pending']['active'] == desired
            else:
                assert disk['revision'] == previous['revision'] + 1 and 'pending' not in disk
            direct = matrix(bindings, [], previous['revision'] + 1)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                row = next(c for c in rest('GET', 'container') if c['.id'] == container['.id'])
                if row.get('stopped') == 'true': break
                time.sleep(.2)
            rest('POST', 'container/start', {'numbers': container['.id']})
            up = settled()
            resumed = core()['namespace']
            updated = aliases()
            assert resumed['active'] == desired and 'pending' not in resumed
            assert all(updated[n] == a for n, a in bindings.items()) and addition in updated
            report[boundary] = {'down': down, 'disk': disk, 'cached_direct': direct,
                                'recovery': up, 'cached_recovered': matrix(updated, desired, resumed['revision'])}
            bindings = updated
        report['final'] = core()
        report['completed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        if damaged:
            rest('PATCH', 'ip/firewall/nat/' + damaged['.id'], {'disabled': 'false'})
        output = ROOT / '.cache/dataplane/core-results.json'
        output.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS core native lifecycle, cached TCP/UDP/HTTP3 and both crash windows')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', default='mc-core-phase3')
    run(parser.parse_args())
