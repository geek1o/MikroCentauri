#!/usr/bin/env python3
"""Pinned engine process proof of policy ordering; native TUN/egress is separate."""
import argparse
import http.server
import json
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

from smoke import ROOT, Resolver, Target, dns_question, port, recv_exact, wait_port

UUID = 'bf000d23-0752-40b4-affe-68f7707a9661'


def request(socks, destination, target_port, host, source='127.0.0.1', tls=False):
    with socket.socket() as s:
        s.settimeout(4)
        s.bind((source, 0))
        s.connect(('127.0.0.1', socks))
        s.sendall(b'\x05\x01\x00')
        assert recv_exact(s, 2) == b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(destination) + struct.pack('!H', target_port))
        head = recv_exact(s, 4)
        assert head[:2] == b'\x05\x00', head
        length = {1: 4, 4: 16}.get(head[3])
        if length is None:
            length = recv_exact(s, 1)[0]
        recv_exact(s, length + 2)
        conn = s
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(s, server_hostname=host)
        try:
            conn.sendall(('GET / HTTP/1.0\r\nHost: ' + host + '\r\n\r\n').encode())
            data = b''
            while True:
                block = conn.recv(4096)
                if not block:
                    break
                data += block
            assert b'mikrocentauri-lab-target' in data
        finally:
            if tls:
                conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sing-box', required=True)
    args = parser.parse_args()
    binary = str(pathlib.Path(args.sing_box).resolve())
    resolver = Resolver()
    plain = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    processes = []
    https = None
    try:
        with tempfile.TemporaryDirectory(prefix='mc-binding-policy-') as work:
            work = pathlib.Path(work)
            cert, key = work / 'cert.pem', work / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=lab.test', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            https = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            https.socket = ctx.wrap_socket(https.socket, server_side=True)
            threading.Thread(target=https.serve_forever, daemon=True).start()
            vless, socks, dns = port(), port(), port()
            server = {'log': {'level': 'info'}, 'inbounds': [{'type': 'vless', 'tag': 'test-vless', 'listen': '127.0.0.1', 'listen_port': vless, 'users': [{'uuid': UUID}]}], 'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'dns': {'servers': [{'type': 'udp', 'tag': 'bootstrap', 'server': '127.0.0.1', 'server_port': resolver.port}], 'final': 'bootstrap'}, 'route': {'final': 'direct', 'default_domain_resolver': 'bootstrap'}}
            client = json.loads((ROOT / 'internal/engineguard/testdata/bounded.json').read_text())
            client['inbounds'] = [{'type': 'direct', 'tag': 'dns-in', 'listen': '127.0.0.1', 'listen_port': dns}, {'type': 'mixed', 'tag': 'explicit-in', 'listen': '127.0.0.1', 'listen_port': socks}]
            client['dns']['servers'][0].update(server='127.0.0.1', server_port=resolver.port)
            client['experimental']['cache_file']['path'] = str(work / 'cache.db')
            client['outbounds'][1].update(server='127.0.0.1', server_port=vless)
            # Host process source aliases replace only the native lab source fixtures.
            client['route']['rules'][1]['source_ip_cidr'] = ['127.0.0.3/32']
            client['route']['rules'][2]['source_ip_cidr'] = ['127.0.0.2/32']

            def start(name, config, listener):
                path = work / (name + '.json')
                path.write_text(json.dumps(config))
                subprocess.run([binary, 'check', '-c', str(path)], check=True, capture_output=True)
                with open(work / (name + '.log'), 'wb') as log:
                    process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
                processes.append(process)
                wait_port(listener, process)
                return process

            start('server', server, vless)
            process = start('client', client, socks)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as q:
                q.settimeout(3)
                q.sendto(dns_question('selected.test', 1), ('127.0.0.1', dns))
                answer = q.recv(2048)
                alias = socket.inet_ntoa(answer[-4:])
                assert alias.startswith('198.18.')

            def check(name, destination, host, expected_proxy, source='127.0.0.1', tls=False):
                before = (work / 'server.log').read_text().count('inbound connection to')
                request(socks, destination, https.server_address[1] if tls else plain.server_address[1], host, source, tls)
                time.sleep(.05)
                after = (work / 'server.log').read_text().count('inbound connection to')
                assert after - before == int(expected_proxy), (name, before, after)
                print('PASS', name, 'PROXY' if expected_proxy else 'DIRECT')

            for host in ['selected.test', 'Selected.Test', 'selected.test.', alias, 'unselected.test']:
                check('FakeIP HTTP Host=' + host, alias, host, True)
            for host in ['selected.test', 'SeLeCtEd.TeSt', 'unselected.test']:
                check('FakeIP TLS SNI=' + host, alias, host, True, tls=True)
            # macOS has only the configured 127.0.0.1 loopback alias. Separate
            # engine runs adapt the source fixture, rather than modifying host
            # interfaces or claiming native device-identity coverage.
            process.terminate()
            process.wait(3)
            client['route']['rules'][1]['source_ip_cidr'] = ['127.0.0.1/32']
            process = start('direct-source', client, socks)
            check('DIRECT source precedes selected binding', alias, 'unselected.test', False)
            process.terminate()
            process.wait(3)
            client['route']['rules'][1]['source_ip_cidr'] = ['127.0.0.3/32']
            client['route']['rules'][2]['source_ip_cidr'] = ['127.0.0.1/32']
            process = start('proxy-source', client, socks)
            check('PROXY source precedes unselected destination', '127.0.0.1', 'unselected.test', True)
            process.terminate()
            process.wait(3)
            client['route']['rules'][2]['source_ip_cidr'] = ['127.0.0.2/32']
            process = start('cohost', client, socks)
            check('Real-IP selected cohost remains selected after sniff', '127.0.0.1', 'selected.test', True)
            check('Real-IP unselected cohost remains DIRECT', '127.0.0.1', 'unselected.test', False)
            # Reproduce the old failure with the same engine/alias/target: remove
            # only the early binding rule and move sniff before source rules.
            process.terminate()
            process.wait(3)
            rules = client['route']['rules']
            client['route']['rules'] = [rules[0], rules[4], rules[1], rules[2], rules[5]]
            start('unsafe-before', client, socks)
            check('Old ordering reproduces Host policy escape', alias, 'unselected.test', False)
            check('Old ordering reproduces TLS SNI policy escape', alias, 'unselected.test', False, tls=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for target in [plain, https]:
            if target:
                target.shutdown()
                target.server_close()
        resolver.close()
    print('NOT RUN: native TUN, RouterOS egress, QUIC, reboot')


if __name__ == '__main__':
    main()
