#!/usr/bin/env python3
"""Endpoint churn and retained cached aliases in the isolated localhost CHR lab."""
import argparse
import json
import time
import urllib.request
from chr_dataplane import ROOT, rest, request, assert_success, gateway
from chr_dynamic_publication import wait, maps, publish
from chr_protocols import quic


def fixture(target='10.77.0.20', fail=False):
    q = urllib.request.Request('http://127.0.0.1:19020/dns-fixture',
        data=json.dumps({'target': target, 'ttl': 5, 'fail': fail}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(q, timeout=5) as r:
        return json.load(r)


def cached(domain, alias, udp=False):
    endpoint = 'udp' if udp else 'request'
    q = urllib.request.Request('http://127.0.0.1:19010/'+endpoint,
        data=json.dumps({'domain': domain, 'address': alias, 'skip_dns': True,
                         'path': '/phase4-cached-'+domain, 'payload': 'phase4-churn-udp'}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(q, timeout=16) as r:
        return json.load(r)


def mapping(alias, target, timeout=25):
    started = time.monotonic()
    while time.monotonic()-started < timeout:
        found = [m for m in maps() if m.get('dst-address') == alias]
        if len(found) == 1 and found[0]['to-addresses'] == target:
            return found[0]
        time.sleep(.3)
    raise AssertionError({'alias': alias, 'target': target, 'maps': maps()})


def protocols(alias, target, peer):
    tcp = cached('second.test', alias)
    udp = cached('second.test', alias, True)
    h3 = quic('second.test', alias)
    assert_success(tcp, peer)
    assert tcp['target']['local_ip'] == target, tcp
    assert_success(udp)
    assert h3['remote_ip'] == peer, h3
    return {'tcp': tcp, 'udp': udp, 'http3': h3}


if __name__ == '__main__':
    assert rest('GET', 'system/resource')['board-name'].startswith('CHR ')
    parser = argparse.ArgumentParser()
    parser.add_argument('--container', default='mc-gateway-phase4')
    parser.add_argument('--admission', action='store_true', help='Require a fresh admitted generation after blocked startup')
    args = parser.parse_args()
    container_name = args.container
    c = next(c for c in rest('GET','container') if c['name']==container_name)
    result = {'initial': wait(True), 'scope': 'Two real targets, one immutable alias; new TCP/UDP/HTTP3 connections only'}
    blocked = None
    try:
        fixture()
        first, attempts = publish('second.test')
        alias = first['resolved_ipv4']
        result['initial_publication'] = {'attempts': attempts, 'alias': alias,
            'map': mapping(alias, '10.77.0.20')}
        result['churn_fixture'] = fixture('10.77.0.21')
        result['changed_map'] = mapping(alias, '10.77.0.21')
        assert result['changed_map']['.id'] == result['initial_publication']['map']['.id'], 'Rule recreated'
        # Let the engine's independent real-DNS cache expire before proxy traffic.
        time.sleep(6)
        result['proxy_after_churn'] = protocols(alias, '10.77.0.21', '10.77.0.10')
        rest('POST', 'container/stop', {'numbers': c['.id']})
        result['container_down'] = wait(False)
        result['cached_direct_after_churn'] = protocols(alias, '10.77.0.21', '10.77.0.1')
        rest('POST', 'container/start', {'numbers': c['.id']})
        result['container_up'] = wait(True)
        rest('POST','ip/dns/cache/flush',{})
        restored, attempts = publish('second.test')
        assert restored['resolved_ipv4'] == alias, restored
        result['restart_publication'] = {'attempts': attempts, 'map': mapping(alias, '10.77.0.21')}
        result['dns_failure_fixture'] = fixture('10.77.0.21', True)
        result['expired_resolution_down'] = wait(False)
        result['retained_map'] = mapping(alias, '10.77.0.21')
        result['cached_direct_with_dns_failure'] = protocols(alias, '10.77.0.21', '10.77.0.1')
        # Force UP interceptors ONLY in the disposable lab while monitor stays DOWN,
        # to witness gate refusal rather than ordinary native DIRECT DNS behavior.
        rest('POST','system/script/run',{'number':'mc-lab-up'})
        time.sleep(1)
        rest('POST','ip/dns/cache/flush',{})
        denied = request('second.test', path='/expired-must-not-publish')
        assert denied.get('error') and not denied.get('resolved_ipv4'), denied
        result['expired_publication_denied'] = denied
        rest('POST','system/script/run',{'number':'mc-lab-down'})
        result['dns_diagnostics'] = gateway(path='/diagnostics/dns')
        # Save a real-target transition while its control transport is blocked.
        # The old native map must keep serving cached addresses even after a
        # full container restart. Restore transport to complete the intent.
        blocked = rest('PUT','ip/firewall/filter', {'chain':'input','action':'reject',
            'reject-with':'tcp-reset','src-address':'172.30.0.2','dst-address':'172.30.0.1',
            'protocol':'tcp','dst-port':'80','comment':'disposable-phase4-control-block'})
        fixture('10.77.0.20')
        time.sleep(6)
        # Reconcile stops at the first unavailable map. Explicitly query this
        # expired domain through the gate so its own target intent is written.
        rest('POST','system/script/run',{'number':'mc-lab-up'})
        time.sleep(1)
        rest('POST','ip/dns/cache/flush',{})
        update_denied = request('second.test',path='/pending-update-must-not-publish')
        assert update_denied.get('error') and not update_denied.get('resolved_ipv4'), update_denied
        result['target_update_denied'] = update_denied
        result['target_update_diagnostics'] = gateway(path='/diagnostics/dns')
        assert result['target_update_diagnostics']['counts'].get('publication/update_error',0)>0, result['target_update_diagnostics']
        rest('POST','system/script/run',{'number':'mc-lab-down'})
        time.sleep(1)
        result['control_outage_map'] = mapping(alias, '10.77.0.21')
        result['control_outage_cached_direct'] = protocols(alias, '10.77.0.21', '10.77.0.1')
        rest('POST','container/stop',{'numbers':c['.id']})
        rest('POST','container/start',{'numbers':c['.id']})
        time.sleep(5)
        result['restart_during_control_outage_map'] = mapping(alias, '10.77.0.21')
        result['restart_during_control_outage_direct'] = protocols(alias, '10.77.0.21', '10.77.0.1')
        if args.admission:
            # The lab HTTP server starts after the bounded startup attempt.
            # While admission is pending it may still refuse connections.
            deadline = time.monotonic()+30
            while True:
                try:
                    result['restart_admission_denied'] = gateway(path='/diagnostics/generation')
                    break
                except RuntimeError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(.2)
            assert not result['restart_admission_denied']['admission']['admitted']
            assert not result['restart_admission_denied']['engine_running']
            assert 'blackhole default' in result['restart_admission_denied']['ingress_route']
        rest('DELETE','ip/firewall/filter/'+blocked['.id'])
        blocked = None
        if args.admission:
            result['fresh_admission'] = gateway('post','/control/start')
        result['returned_map'] = mapping(alias, '10.77.0.20')
        result['recovered_up'] = wait(True)
        rest('POST','ip/dns/cache/flush',{})
        last, attempts = publish('second.test')
        assert last['resolved_ipv4'] == alias, last
        result['final_publication'] = {'attempts': attempts, 'map': mapping(alias, '10.77.0.20')}
        time.sleep(6)
        result['final_proxy'] = protocols(alias, '10.77.0.20', '10.77.0.10')
        result['final_diagnostics'] = gateway(path='/diagnostics/dns')
        result['completed'] = True
    except Exception as error:
        result['error'] = str(error)
        raise
    finally:
        if blocked is not None:
            rest('DELETE','ip/firewall/filter/'+blocked['.id'])
        fixture()
        rest('POST','system/script/run',{'number':'mc-lab-down'})
        out = ROOT/'.cache/dataplane/target-refresh-results.json'
        out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
