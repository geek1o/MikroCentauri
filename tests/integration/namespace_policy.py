#!/usr/bin/env python3
"""Stock-engine namespace expansion/retirement proof; public DNS/native are separate."""
import argparse
import copy
import http.server
import ipaddress
import json
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from binding_policy import UUID, request
from smoke import ROOT, Resolver, Target, dns_question, port, wait_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sing-box', required=True)
    args = parser.parse_args()
    binary = str(pathlib.Path(args.sing_box).resolve())
    resolver = Resolver()
    plain = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    processes, https = [], None
    try:
        with tempfile.TemporaryDirectory(prefix='mc-namespace-policy-') as directory:
            work = pathlib.Path(directory)
            cert, key = work / 'cert.pem', work / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=lab.test', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            https = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            https.socket = tls.wrap_socket(https.socket, server_side=True)
            threading.Thread(target=https.serve_forever, daemon=True).start()
            vless, socks, dns = port(), port(), port()
            server = {
                'log': {'level': 'info'},
                'inbounds': [{'type': 'vless', 'tag': 'test-vless', 'listen': '127.0.0.1', 'listen_port': vless, 'users': [{'uuid': UUID}]}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                'dns': {'servers': [{'type': 'udp', 'tag': 'bootstrap', 'server': '127.0.0.1', 'server_port': resolver.port}], 'final': 'bootstrap'},
                'route': {'final': 'direct', 'default_domain_resolver': 'bootstrap'},
            }
            base = json.loads((ROOT / 'internal/engineguard/testdata/bounded.json').read_text())
            base['inbounds'] = [
                {'type': 'direct', 'tag': 'dns-in', 'listen': '127.0.0.1', 'listen_port': dns},
                {'type': 'mixed', 'tag': 'explicit-in', 'listen': '127.0.0.1', 'listen_port': socks},
            ]
            base['dns']['servers'][0].update(server='127.0.0.1', server_port=resolver.port)
            base['experimental']['cache_file']['path'] = str(work / 'cache.db')
            base['outbounds'][1].update(server='127.0.0.1', server_port=vless)

            def config(namespace, active, source_override=None):
                cfg = copy.deepcopy(base)
                for rule in cfg['dns']['rules']:
                    rule['domain'] = namespace[:]
                retired = [name for name in namespace if name not in active]
                rules = [
                    {'action': 'hijack-dns', 'inbound': ['dns-in']},
                    {'action': 'route', 'source_ip_cidr': ['127.0.0.1/32' if source_override == 'direct' else '127.0.0.3/32'], 'outbound': 'direct'},
                    {'action': 'route', 'source_ip_cidr': ['127.0.0.1/32' if source_override == 'proxy' else '127.0.0.2/32'], 'outbound': 'proxy'},
                    {'action': 'route', 'domain': active[:], 'outbound': 'proxy'},
                ]
                if retired:
                    rules.append({'action': 'route', 'domain': retired, 'outbound': 'direct'})
                rules.extend([{'action': 'sniff'}, {'action': 'route', 'domain': active[:], 'outbound': 'proxy'}])
                cfg['route']['rules'] = rules
                return cfg

            def start(name, cfg, listener):
                path = work / (name + '.json')
                path.write_text(json.dumps(cfg))
                subprocess.run([binary, 'check', '-c', str(path)], check=True, capture_output=True)
                with open(work / (name + '.log'), 'wb') as log:
                    process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
                processes.append(process)
                wait_port(listener, process)
                return process

            def close(process):
                process.terminate()
                # Failure to close cleanly is a test failure: this proof depends
                # on stock engine Close persisting allocation cursor metadata.
                assert process.wait(5) == 0, 'engine did not close cleanly'

            def alias(name):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as query:
                    query.settimeout(3)
                    packet = dns_question(name, 1)
                    query.sendto(packet, ('127.0.0.1', dns))
                    answer = query.recv(2048)
                ident, flags, questions, answers, _, _ = struct.unpack('!6H', answer[:12])
                assert ident == 0x4d43 and flags & 15 == 0 and questions == 1 and answers == 1, name
                result = socket.inet_ntoa(answer[-4:])
                assert ipaddress.ip_address(result) in ipaddress.ip_network('198.18.0.0/15'), (name, result)
                return result

            def check(label, destination, host, proxy, use_tls=False):
                log = work / 'server.log'
                before = log.read_text().count('inbound connection to')
                request(socks, destination, https.server_address[1] if use_tls else plain.server_address[1], host, tls=use_tls)
                time.sleep(.05)
                after = log.read_text().count('inbound connection to')
                assert after - before == int(proxy), (label, before, after)
                print('PASS', label, 'PROXY' if proxy else 'DIRECT')

            initial = ['selected.test', 'second.test', 'third.test']
            expanded = initial + ['fourth.test']
            active = ['selected.test', 'third.test', 'fourth.test']
            start('server', server, vless)
            process = start('initial', config(initial, initial), socks)
            bindings = {name: alias(name) for name in initial}
            assert len(set(bindings.values())) == len(initial)
            check('initial second binding', bindings['second.test'], 'unselected.test', True)
            close(process)

            process = start('retired-expanded', config(expanded, active), socks)
            observed = {name: alias(name) for name in expanded}
            assert all(observed[name] == bindings[name] for name in initial), (bindings, observed)
            assert len(set(observed.values())) == len(expanded), observed
            bindings = observed
            print('PASS graceful expansion retains old aliases and allocates one unique addition', json.dumps(bindings, sort_keys=True))
            for host in ['second.test', 'selected.test', 'SeLeCtEd.TeSt', 'selected.test.', bindings['second.test']]:
                check('retired cached alias HTTP Host=' + host, bindings['second.test'], host, False)
            for host in ['second.test', 'selected.test', 'SeLeCtEd.TeSt']:
                check('retired cached alias TLS SNI=' + host, bindings['second.test'], host, False, True)
            check('active alias cannot sniff into retired', bindings['selected.test'], 'second.test', True)
            check('new active alias', bindings['fourth.test'], 'second.test', True)
            close(process)

            process = start('reopened', config(expanded, active), socks)
            assert {name: alias(name) for name in expanded} == bindings
            check('retirement survives engine reopen', bindings['second.test'], 'selected.test', False)
            close(process)
            # Adapt only fixture source predicates; macOS need not add loopback
            # interfaces and this does not establish native device coverage.
            for outbound, expected in [('direct', False), ('proxy', True)]:
                process = start('source-' + outbound, config(expanded, active, outbound), socks)
                check(outbound + ' source precedes retired alias', bindings['second.test'], 'selected.test', expected)
                check(outbound + ' source precedes active alias', bindings['selected.test'], 'second.test', expected)
                close(process)

            process = start('reactivated', config(expanded, expanded), socks)
            assert {name: alias(name) for name in expanded} == bindings
            check('reactivation reuses second alias with HTTP foreign Host', bindings['second.test'], 'unselected.test', True)
            check('reactivation reuses second alias with TLS foreign SNI', bindings['second.test'], 'unselected.test', True, True)
            close(process)

            unsafe = config(expanded, active)
            unsafe['route']['rules'] = [rule for rule in unsafe['route']['rules'] if not (rule.get('domain') == ['second.test'] and rule.get('outbound') == 'direct')]
            process = start('unsafe-retirement', unsafe, socks)
            check('missing retired terminal rule reproduces HTTP reselection', bindings['second.test'], 'selected.test', True)
            check('missing retired terminal rule reproduces TLS reselection', bindings['second.test'], 'selected.test', True, True)
            close(process)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for target in [plain, https]:
            if target:
                target.shutdown()
                target.server_close()
        resolver.close()
    print('NOT RUN: public DNS retirement, controller durability, native TUN/RouterOS egress, QUIC, abrupt crash')
    print('TLS certificate validation disabled only to isolate SNI policy in this host process fixture')


if __name__ == '__main__':
    main()
