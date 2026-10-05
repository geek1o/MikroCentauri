#!/usr/bin/env python3
"""Activation crash/recovery acceptance on the disposable localhost CHR only.

Requires the prepared five-name namespace and MC_ACTIVATION_FAULTS=1 lab image.
Every workload opens a new connection. UDP egress is evidenced separately by
phase8 capture markers; a successful UDP response alone does not identify peer.
"""
import base64
import itertools
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import json
import time
import urllib.error
import urllib.request

from chr_dataplane import ROOT, rest, gateway, request, assert_success
from chr_dynamic_publication import wait, maps, COMMENTS
from chr_binding_policy import workload
from chr_protocols import quic
from chr_namespace import settled_up

OUTPUT = ROOT / '.cache/dataplane/activation-results.json'
CONTAINER = 'mc-gateway-phase7'
CONTAINER_ROOT = 'pcie2/mc-gateway-phase5'
NAMES = ['selected.test', 'second.test', 'third.test', 'fourth.test', 'fifth.test']
sequence = itertools.count(1)
current_report = None
snapshot_event = threading.Event()
snapshot_lock = threading.Lock()
snapshot_value = None


class SnapshotCollector(BaseHTTPRequestHandler):
    def do_POST(self):
        global snapshot_value
        if self.path != "/snapshot":
            self.send_error(404)
            return
        try:
            self.connection.settimeout(5)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1048576:
                raise ValueError("invalid snapshot size")
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict) or "revision" not in value:
                raise ValueError("invalid snapshot")
        except (ValueError, UnicodeError) as error:
            (ROOT / '.cache/dataplane/activation-snapshot-error.txt').write_text(str(error) + '\n' + str(self.headers))
            self.send_error(400)
            return
        with snapshot_lock:
            snapshot_value = value
            snapshot_event.set()
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def write_report(report):
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2) + '\n')


def native_snapshot():
    """Read-only native objects, retaining complete owned rows at each barrier."""
    return {
        'selectors': [r for p in ('ip/route', 'ip/firewall/nat')
                      for r in rest('GET', p) if r.get('comment') in COMMENTS],
        'maps': maps(),
        'observer': [r for r in rest('GET', 'tool/netwatch')
                     if r.get('comment') == 'mikrocentauri:lab:netwatch:readiness'],
        'lease': [r for r in rest('GET', 'ip/firewall/address-list')
                  if r.get('list') == 'mc-lab-up-lease'],
    }


def disk_policy():
    # Parent provisions this fixed-path administrative script and removes it
    # after acceptance. Its only read is the disposable namespace journal.
    global snapshot_value
    with snapshot_lock:
        snapshot_value = None
        snapshot_event.clear()
    admin_fixture_post('system/script/run', {'number': 'mc-lab-activation-snapshot'})
    if not snapshot_event.wait(10):
        raise AssertionError('No native journal snapshot received')
    with snapshot_lock:
        return dict(snapshot_value)


def container_stopped(container, timeout=45):
    observations = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = next(r for r in rest('GET', 'container') if r['.id'] == container['.id'])
        observations.append(row)
        if row.get('stopped') == 'true':
            return observations
        time.sleep(.25)
    raise AssertionError({'container_not_stopped': observations})


def policy():
    return gateway(path='/diagnostics/namespace')


def bindings():
    return {b['domain']: b['alias'] for b in gateway(path='/diagnostics/generation')['admission']['bindings']}


def apply(revision, active):
    rows = rest('POST', 'tool/fetch', {
        'url': 'http://172.30.0.2:9099/control/namespace', 'http-method': 'post',
        'http-data': json.dumps({'revision': revision, 'active': active}),
        'http-header-field': 'Content-Type: application/json', 'output': 'user'})
    return next(json.loads(r['data']) for r in rows if r.get('data'))


def arm(point):
    assert point in ('after-verify', 'before-release')
    marker = ROOT / '.cache/dataplane/activation-fault'
    marker.write_text(point + '\n')
    # Fixed disposable admin/blank-password fixture only: container /data is
    # private and the normal restricted mc-lab account cannot write this marker.
    body = {'url': 'http://10.0.2.2:18082/activation-fault',
            'dst-path': CONTAINER_ROOT + '/data/activation-fault'}
    rows = admin_fixture_post('tool/fetch', body)
    assert any(r.get('status') == 'finished' for r in rows), rows


def admin_fixture_post(path, body):
    # Test provisioning/snapshot only; never used by the running controller.
    assert path in ('tool/fetch', 'system/script/run')
    req = urllib.request.Request('http://127.0.0.1:18080/rest/' + path,
        data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
        'Authorization': 'Basic ' + base64.b64encode(b'admin:').decode()})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)



def expect_denied(revision, active):
    try:
        apply(revision, active)
    except RuntimeError as error:
        return str(error)
    raise AssertionError('Invalid or damaged candidate was admitted')


def crash_apply(revision, active):
    try:
        result = apply(revision, active)
    except (RuntimeError, urllib.error.URLError, TimeoutError) as error:
        return str(error)
    raise AssertionError({'crash_did_not_interrupt_apply': result})


def matrix(aliases, active, revision):
    result = {}
    current_report['in_progress_matrix'] = {'revision': revision, 'active': list(active), 'results': result}
    write_report(current_report)
    for name, alias in aliases.items():
        peer = '10.77.0.10' if name in active else '10.77.0.1'
        result[name] = {'expected_peer': peer}
        http = workload('selected.test', domain=name, address=alias)
        result[name]['http_foreign_active_host'] = http
        write_report(current_report)
        assert_success(http, peer)
        h3 = quic('selected.test', alias)
        result[name]['http3_verified_active_sni'] = h3
        write_report(current_report)
        assert h3['remote_ip'] == peer, h3
        marker = f'phase8-{revision}-{name}-{next(sequence)}'
        req = urllib.request.Request('http://127.0.0.1:19010/udp',
            data=json.dumps({'domain': name, 'address': alias, 'skip_dns': True, 'payload': marker}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=16) as response:
            udp = json.load(response)
        udp['capture_marker'] = marker
        result[name]['udp'] = udp
        write_report(current_report)
        assert_success(udp)
    current_report.pop('in_progress_matrix', None)
    return result


def assert_quarantined():
    diagnostic = gateway(path='/diagnostics/generation')
    assert not diagnostic['engine_running'] and not diagnostic['admission']['admitted'], diagnostic
    assert 'blackhole' in diagnostic['ingress_route'], diagnostic
    return diagnostic



def control_outage(aliases, current):
    """Reject native proof transport; intent must not Prepare or Release."""
    result = {}
    block = rest('PUT', 'ip/firewall/filter', {
        'chain': 'input', 'action': 'reject', 'reject-with': 'tcp-reset',
        'src-address': '172.30.0.2', 'dst-address': '172.30.0.1',
        'protocol': 'tcp', 'dst-port': '80',
        'comment': 'mikrocentauri:lab:fault:activation-rest'})
    try:
        wanted = [n for n in current['known'] if n != 'second.test']
        result['denied'] = expect_denied(current['revision'], wanted)
        result['policy'] = policy()
        assert result['policy'] == current, result['policy']
        result['quarantined'] = assert_quarantined()
        result['down'] = wait(False)
        result['native'] = native_snapshot()
        result['cached_direct'] = matrix(aliases, [], current['revision'])
    finally:
        rest('DELETE', 'ip/firewall/filter/' + block['.id'])
    result['recovery'] = gateway(method='post', path='/control/start')
    result['recovered_up'] = settled_up()
    assert policy() == current and bindings() == aliases
    result['recovered_matrix'] = matrix(aliases, current['active'], current['revision'])
    return result


def run():
    global current_report
    report = {'scope': 'Five immutable IPv4 aliases; new HTTP/HTTP3/UDP connections; injected process death, not power loss'}
    current_report = report
    collector = ThreadingHTTPServer(('127.0.0.1', 19082), SnapshotCollector)
    collector_thread = threading.Thread(target=collector.serve_forever, daemon=True)
    collector_thread.start()
    fault = None
    try:
        assert rest('GET', 'system/resource')['board-name'].startswith('CHR ')
        container = next(r for r in rest('GET', 'container') if r['name'] == CONTAINER)
        report['initial_up'] = settled_up()
        current = policy()
        assert current['known'] == NAMES and not current.get('pending'), current
        if current['active'] != NAMES:
            current = apply(current['revision'], NAMES)
            report['baseline_reactivation'] = current
            settled_up()
        original = bindings()
        assert original == {name: f'198.18.0.{i + 2}' for i, name in enumerate(NAMES)}, original
        report['initial_policy'] = current
        report['original_bindings'] = original
        report['initial_native'] = native_snapshot()
        retired = [n for n in NAMES if n != 'second.test']
        current = apply(current['revision'], retired)
        report['retired_policy'] = current
        report['retired_up'] = settled_up()
        assert bindings() == original
        rest('POST', 'ip/dns/cache/flush', {})
        dns = request('second.test', path='/phase8-retired-new-dns')
        assert_success(dns, '10.77.0.1')
        assert dns['resolved_ipv4'] == '10.77.0.20', dns
        report['retired_new_dns'] = dns
        report['retired_matrix'] = matrix(original, retired, current['revision'])
        report['source_overrides'] = {}
        for source, peer in [('192.168.88.20', '10.77.0.10'), ('192.168.88.30', '10.77.0.1')]:
            http = workload('selected.test', source=source)
            assert_success(http, peer)
            h3 = quic('selected.test', original['second.test'], source)
            assert h3['remote_ip'] == peer, h3
            report['source_overrides'][source] = {'http': http, 'http3': h3}
        report['invalid_candidates'] = {}
        for label, rev, candidate in [
            ('stale', current['revision'] - 1, NAMES),
            ('duplicate', current['revision'], ['selected.test', 'selected.test']),
            ('capacity', current['revision'], ['selected.test'] + [f'overflow{i}.test' for i in range(32)]),
        ]:
            before = gateway(path='/diagnostics/generation')
            denied = expect_denied(rev, candidate)
            after = gateway(path='/diagnostics/generation')
            assert policy() == current and bindings() == original
            assert after['engine_running'] and after['admission']['admitted'], after
            assert before['admission']['epoch'] == after['admission']['epoch'], (before, after)
            report['invalid_candidates'][label] = {'denied': denied, 'before': before, 'after': after}
        write_report(report)

        arm('after-verify')
        report['after_verify_interruption'] = crash_apply(current['revision'], NAMES)
        report['after_verify_container_stop'] = container_stopped(container)
        report['after_verify_disk'] = disk_policy()
        pending = report['after_verify_disk']
        assert pending['revision'] == current['revision'] and pending['pending']['revision'] == current['revision'] + 1, pending
        assert pending['pending']['active'] == NAMES
        report['after_verify_down'] = wait(False)
        report['after_verify_native'] = native_snapshot()
        report['after_verify_cached_direct'] = matrix(original, [], pending['pending']['revision'])
        write_report(report)
        rest('POST', 'container/start', {'numbers': container['.id']})
        report['after_verify_recovered_up'] = settled_up()
        current = policy()
        assert not current.get('pending') and current['revision'] == pending['pending']['revision'] and current['active'] == NAMES, current
        assert bindings() == original
        report['after_verify_recovered_policy'] = current
        report['after_verify_recovered_matrix'] = matrix(original, NAMES, current['revision'])

        arm('before-release')
        report['before_release_interruption'] = crash_apply(current['revision'], retired)
        report['before_release_container_stop'] = container_stopped(container)
        committed = disk_policy()
        report['before_release_disk'] = committed
        assert not committed.get('pending') and committed['revision'] == current['revision'] + 1 and committed['active'] == retired, committed
        report['before_release_down'] = wait(False)
        report['before_release_native'] = native_snapshot()
        report['before_release_cached_direct'] = matrix(original, [], committed['revision'])
        write_report(report)
        rest('POST', 'container/start', {'numbers': container['.id']})
        report['before_release_recovered_up'] = settled_up()
        current = policy()
        assert current['revision'] == committed['revision'] and current['active'] == retired and not current.get('pending'), current
        assert bindings() == original
        report['before_release_recovered_policy'] = current
        report['before_release_recovered_matrix'] = matrix(original, retired, current['revision'])

        fault = next(r for r in maps() if r['dst-address'] == original['third.test'])
        rest('PATCH', 'ip/firewall/nat/' + fault['.id'], {'disabled': 'true'})
        wanted = [n for n in retired if n != 'third.test']
        report['backend_denied'] = expect_denied(current['revision'], wanted)
        pending = policy()
        report['backend_pending_policy'] = pending
        assert pending['revision'] == current['revision'] and pending['pending']['active'] == wanted, pending
        report['backend_down'] = wait(False)
        report['backend_native_damaged'] = native_snapshot()
        report['backend_quarantined'] = assert_quarantined()
        rest('POST', 'container/stop', {'numbers': container['.id']})
        report['backend_container_stop'] = container_stopped(container)
        rest('POST', 'container/start', {'numbers': container['.id']})
        deadline = time.monotonic() + 45
        while True:
            try:
                restarted = policy()
                diagnostic = assert_quarantined()
                break
            except (RuntimeError, urllib.error.URLError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.5)
        assert restarted == pending, (restarted, pending)
        report['backend_restart_pending'] = restarted
        report['backend_restart_quarantined'] = diagnostic
        report['backend_restart_native_damaged'] = native_snapshot()
        # Restore exact owned map before DIRECT checks. No traffic guarantee is
        # asserted while a fallback mapping has deliberately been disabled.
        rest('PATCH', 'ip/firewall/nat/' + fault['.id'], {'disabled': 'false'})
        fault = None
        report['backend_restored_direct'] = matrix(original, [], pending['pending']['revision'])
        report['backend_recover_start'] = gateway(method='post', path='/control/start')
        report['backend_recovered_up'] = settled_up()
        current = policy()
        assert current['revision'] == pending['pending']['revision'] and current['active'] == wanted and not current.get('pending'), current
        assert bindings() == original
        report['backend_recovered_policy'] = current
        report['backend_recovered_matrix'] = matrix(original, wanted, current['revision'])
        current = apply(current['revision'], NAMES)
        report['final_up'] = settled_up()
        assert current['active'] == NAMES and bindings() == original and not current.get('pending')
        report['final_policy'] = current
        report['final_native'] = native_snapshot()
        report['final_matrix'] = matrix(original, NAMES, current['revision'])
        report['control_outage'] = control_outage(original, current)
        report['completed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if fault:
            try:
                rest('PATCH', 'ip/firewall/nat/' + fault['.id'], {'disabled': 'false'})
                report['fault_map_restored_in_cleanup'] = True
            except Exception as error:
                report['cleanup_error'] = str(error)
        write_report(report)
        collector.shutdown()
        collector.server_close()
        collector_thread.join(timeout=2)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    run()
