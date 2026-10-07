#!/usr/bin/env python3
"""Full App provisioning/native owner on a separate prepared CHR network clone.

Only synthetic private fixtures; default production image/entrypoint. Management
ports and LAN/WAN switches differ from the original lab. Never prints credentials.
"""
import argparse, base64, datetime, hashlib, http.client, http.server, io, json
import pathlib, re, socket, ssl, subprocess, tarfile, threading, time, urllib.request, uuid
from chr_dataplane import request, assert_success
from chr_binding_policy import workload
from chr_protocols import quic
from chr_app_swap import AppSwap


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci', type=pathlib.Path, default=pathlib.Path('.cache/app-image-final/oci'))
    parser.add_argument('--work', type=pathlib.Path, default=pathlib.Path('.cache/app-native'))
    parser.add_argument('--rollback-oci', type=pathlib.Path, default=pathlib.Path('.cache/app-image-complete/oci'))
    args = parser.parse_args()
    work = args.work.resolve(); private = work / 'private'; private.mkdir(exist_ok=True); private.chmod(0o700)
    report = {'routeros': '7.24.5 (stable)', 'scope': 'production App native owner; separate clone; synthetic fixtures'}
    name = 'mc-native-' + uuid.uuid4().hex[:8]
    report['run_id'] = str(time.time_ns())
    udp_sequence = 0
    auth = 'Basic ' + base64.b64encode(b'admin:').decode()

    def native(method, path, body=None):
        req = urllib.request.Request('http://127.0.0.1:18336/rest/' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': auth, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                raw = response.read(); return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            raise RuntimeError(f'native {method} {path}: HTTP {e.code}') from None

    def clock():
        now = datetime.datetime.now(datetime.timezone.utc)
        native('POST', 'system/clock/set', {'time-zone-autodetect': 'false', 'time-zone-name': 'Etc/UTC',
            'date': now.strftime('%Y-%m-%d'), 'time': now.strftime('%H:%M:%S')})

    def settle(fn, label, timeout=180):
        deadline = time.monotonic() + timeout; synced = 0
        while time.monotonic() < deadline:
            if time.monotonic() - synced > 10:
                clock(); synced = time.monotonic()
            try:
                result = fn()
                if result: return result
            except (OSError, RuntimeError, AssertionError, http.client.HTTPException): pass
            time.sleep(.5)
        raise AssertionError('native App timeout: ' + label)

    def sftp(commands):
        batch = private / 'transfer.batch'; batch.write_text('\n'.join(commands) + '\n'); batch.chmod(0o600)
        subprocess.run(['sftp', '-b', str(batch), '-P', '22336', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(private / 'known_hosts'),
            'admin@127.0.0.1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)

    def marked_udp(domain):
        nonlocal udp_sequence
        udp_sequence += 1
        marker = 'phase4-' + report['run_id'] + '-1-' + domain + '-' + str(udp_sequence)
        req = urllib.request.Request('http://127.0.0.1:19010/udp',
            data=json.dumps({'domain': domain, 'payload': marker}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=16) as response: result = json.load(response)
        assert_success(result)
        assert result['payload'] == marker
        result['capture_marker'] = marker
        return result

    def certificate(stem, san):
        cert, key = private / (stem + '.crt'), private / (stem + '.key')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
            '-out', str(cert), '-days', '2', '-subj', '/CN=' + stem, '-addext', 'subjectAltName=' + san],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert.chmod(0o600); key.chmod(0o600); return cert, key

    def read_file(path):
        rows = native('POST', 'file/read', {'file': path, 'offset': '0', 'chunk-size': '32768'})
        if isinstance(rows, dict): rows = [rows]
        return ''.join(r.get('data', '') for r in rows)

    clock(); resource = native('GET', 'system/resource')
    assert resource['version'] == report['routeros'] and resource['board-name'].startswith('CHR ')
    assert all(c.get('stopped') == 'true' or (c.get('name') == 'mc-core-phase3-first-import'
        and c.get('running') != 'true') or (c.get('name', '').startswith('app-mc-native-')
        and not c.get('image-id') and c.get('running') != 'true') for c in native('GET', 'container'))
    disk = next(d['slot'] for d in native('GET', 'disk') if d.get('mounted') == 'true' and d.get('fs') == 'ext4')
    blobs = {}
    def load_image(layout):
        descriptor = next(m for m in json.loads((layout / 'index.json').read_text())['manifests']
                          if m['platform']['architecture'] == 'amd64')
        manifest = json.loads((layout / 'blobs/sha256' / descriptor['digest'][7:]).read_bytes())
        for entry in [descriptor, manifest['config']] + manifest['layers']:
            raw = (layout / 'blobs/sha256' / entry['digest'][7:]).read_bytes()
            assert 'sha256:' + hashlib.sha256(raw).hexdigest() == entry['digest']; blobs[entry['digest']] = raw
        return descriptor, manifest
    descriptor, manifest = load_image(args.oci.resolve())
    rollback_descriptor, rollback_manifest = load_image(args.rollback_oci.resolve())
    assert manifest['config']['digest'] != rollback_manifest['config']['digest']
    report['image_manifest'] = descriptor['digest']; report['image_config'] = manifest['config']['digest']
    registry_cert, registry_key = certificate(name + '-registry', 'IP:10.0.2.2')

    class Registry(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self):
            match = re.fullmatch(r'/v2/mikrocentauri/(manifests|blobs)/(sha256:[a-f0-9]{64})', self.path)
            if self.path == '/v2/': raw, kind = b'{}', 'application/json'
            elif match and match[2] in blobs:
                raw = blobs[match[2]]; kind = 'application/octet-stream' if match[1] == 'blobs' else json.loads(raw)['mediaType']
            else: self.send_error(404); return
            self.send_response(200); self.send_header('Content-Type', kind)
            self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
            self.send_header('Docker-Content-Digest', 'sha256:' + hashlib.sha256(raw).hexdigest())
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 18539), Registry)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(registry_cert, registry_key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True); server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    image = 'https://10.0.2.2:18539/mikrocentauri@' + descriptor['digest']
    app_id = None; owned = []; controller_user = None
    token = None; tls = None

    def app(): return native('GET', 'app/' + app_id)
    def core(): return next((c for c in native('GET', 'container') if c.get('name') == 'app-' + name), None)
    def stopped(): return core() and core().get('stopped') == 'true'
    def api(method, path, body=None):
        conn = http.client.HTTPSConnection('127.0.0.1', 18446, timeout=60, context=tls)
        headers = {'Content-Type': 'application/json'}
        if token: headers['Authorization'] = 'Bearer ' + token
        conn.request(method, '/api/v1' + path, json.dumps(body).encode() if body is not None else None, headers)
        response = conn.getresponse(); raw = response.read(); status = response.status; conn.close()
        return status, json.loads(raw) if raw else None

    try:
        # SFTP encrypts transfer; RouterOS does not preserve uploaded Unix modes.
        sftp([f'put -p "{registry_cert}" "{name}-registry.crt"'])
        native('POST', 'certificate/import', {'file-name': name + '-registry.crt', 'passphrase': ''})
        cert_id = next(c['.id'] for c in native('GET', 'certificate') if c.get('common-name') == name + '-registry')
        native('PATCH', 'certificate/' + cert_id, {'trusted': 'true'})
        native('POST', 'app/settings/set', {'disk': disk, 'lan-bridge': 'bridge-lan', 'router-ip': '192.168.88.1'})
        composition = {'name': name, 'auto-update': False, 'services': {'core': {'image': image,
            'ports': ['8443:8443:api-secure'], 'volumes': ['state:/data']}}, 'volumes': {'state': None}}
        app_id = native('PUT', 'app', {'yaml': json.dumps(composition), 'disabled': 'true', 'use-https': 'false'})['.id']
        native('PATCH', 'app/' + app_id, {'disabled': 'false'})
        ip = settle(lambda: app().get('ip-address'), 'VETH allocation')
        settle(lambda: core() and core().get('image-id') == manifest['config']['digest'][7:], 'image extraction')
        native('PATCH', 'app/' + app_id, {'disabled': 'true'}); settle(stopped, 'initial stop')
        container_id = core()['.id']; state = disk + '/apps/' + name + '/state'
        mount = core()['mount']; root = core()['root-dir'].lstrip('/')
        # RouterOS explicitly publishes the actual container interface in App variables.
        interface = re.search(r'\[containerInterface\]=([^,]+)',
                              app()['variables-to-use-in-environment'])[1]
        report['platform'] = {'ip': ip, 'linux_ingress': interface, 'routeros_veth': app()['interface']}
        router_cert, router_key = certificate(name + '-router', 'IP:127.0.0.1,IP:172.18.0.1,IP:10.0.2.15')
        sftp([f'put -p "{router_cert}" "{name}-router.crt"', f'put -p "{router_key}" "{name}-router.key"'])
        for suffix in ('crt', 'key'):
            native('POST', 'certificate/import', {'file-name': name + '-router.' + suffix, 'passphrase': ''})
        router_cert_id = next(c['.id'] for c in native('GET', 'certificate') if c.get('common-name') == name + '-router')
        router_cert_name = native('GET', 'certificate/' + router_cert_id)['name']
        ssl_service = next(s for s in native('GET', 'ip/service') if s['name'] == 'www-ssl')
        native('PATCH', 'ip/service/' + ssl_service['.id'], {'disabled': 'false', 'certificate': router_cert_name})
        user_name = name + '-ctl'; router_password = uuid.uuid4().hex
        controller_user = native('PUT', 'user', {'name': user_name, 'password': router_password, 'group': 'full'})['.id']
        fixture = json.loads(subprocess.run(['.cache/go/bin/go', 'run', './tests/e2e/app_profile',
            '-ip', ip, '-interface', interface], stdout=subprocess.PIPE, check=True, timeout=45).stdout)
        for obj in fixture['objects']:
            assert not any(r.get('comment') == obj['fields']['comment'] for r in native('GET', obj['path']))
            fields = dict(obj['fields'])
            if obj.get('place_before'): fields['place-before'] = obj['place_before']
            if obj['path'] in ('tool/netwatch', 'system/scheduler'): fields['disabled'] = 'false'
            object_id = native('PUT', obj['path'], fields)['.id']; owned.append((obj['path'], object_id))
        for r in native('GET', 'ip/firewall/nat'):
            if r.get('comment') in ('mikrocentauri:lab:nat:dns-tcp', 'mikrocentauri:lab:nat:dns-udp'):
                native('PATCH', 'ip/firewall/nat/' + r['.id'], {'disabled': 'true'})
        app_cert, app_key = certificate('mc-app6-api', 'IP:' + ip + ',IP:127.0.0.1')
        password = 'App6SyntheticOnly-' + uuid.uuid4().hex
        bundle = private / 'bundle'; bootstrap = bundle / 'bootstrap'; bootstrap.mkdir(parents=True, exist_ok=True)
        bundle.chmod(0o700); bootstrap.chmod(0o700)
        settings = {'schema_version': 1, 'data_directory': '/data', 'listen': ip + ':8443',
            'public_origin': 'https://127.0.0.1:18446', 'allow_clients': ['10.0.2.2/32', '192.168.88.0/24'],
            'tls_cert': '/data/bootstrap/server.crt', 'tls_key': '/data/bootstrap/server.key',
            'model': '/data/bootstrap/model.json', 'runtime_profile': '/data/bootstrap/runtime.json',
            'router_config': '/data/bootstrap/router.json', 'password_file': '/data/bootstrap/password'}
        inputs = {'app.json': json.dumps(settings).encode(), 'model.json': json.dumps(fixture['model']).encode(),
            'runtime.json': json.dumps(fixture['profile']).encode(),
            'router.json': json.dumps({'base_url': 'https://172.18.0.1/rest', 'username': user_name,
                'password': router_password, 'ca_file': '/data/bootstrap/router.crt'}).encode(),
            'server.crt': app_cert.read_bytes(), 'server.key': app_key.read_bytes(),
            'router.crt': router_cert.read_bytes(), 'password': password.encode()}
        archive = private / 'install.tar'
        with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as tar:
            for filename, raw in inputs.items():
                path = bootstrap / filename; path.write_bytes(raw); path.chmod(0o600)
                member = tarfile.TarInfo('bootstrap/' + filename); member.mode = 0o600; member.size = len(raw)
                tar.addfile(member, io.BytesIO(raw))
        archive.chmod(0o600)
        provision_dir = disk + '/' + name + '-private'
        sftp([f'mkdir "{provision_dir}"', f'put -p "{archive}" "{provision_dir}/install.tar"'])
        # One-time operator repair is necessary because native SFTP uploads as 0644.
        repair = private / 'provision.sh'
        repair.write_text('set -eu\nchmod 600 /provision/install.tar\nexec /usr/bin/mikrocentauri app-provision -archive /provision/install.tar -data /data\n')
        repair.chmod(0o600)
        sftp([f'put "{repair}" "{provision_dir}/provision.sh"'])
        native('PATCH', 'container/' + container_id, {'entrypoint': '/bin/sh',
            'cmd': '/provision/provision.sh',
            'mount': mount + ',' + provision_dir + ':/provision:rw', 'logging': 'true'})
        native('POST', 'container/start', {'numbers': container_id})
        settle(lambda: json.loads(read_file(state + '/bootstrap/app.json')) == settings, 'Go private provisioning')
        settle(stopped, 'provisioner exit')
        native('PATCH', 'container/' + container_id, {'entrypoint': '', 'cmd': '', 'mount': mount})
        report['provisioning'] = {'go_provisioner': True, 'encrypted_transfer': 'SFTP', 'temporary_mount_removed': True}
        # Exact stopped installation plan/manual flag/verify on native HTTPS.
        operator = private / 'operator.json'
        operator.write_text(json.dumps({'base_url': 'https://127.0.0.1:18436/rest', 'username': user_name,
            'password': router_password, 'ca_file': str(router_cert)})); operator.chmod(0o600)
        common = [str(private / 'mikrocentauri'), '-router-config', str(operator), '-settings-file',
            str(bootstrap / 'app.json'), '-bundle-directory', str(bundle)]
        review = private / 'install-review.json'
        subprocess.run([common[0], 'app-install-plan'] + common[1:] + ['-app', name,
            '-image-ref', image, '-image-config-sha256', manifest['config']['digest'], '-out', str(review)],
            check=True, stdout=subprocess.DEVNULL, timeout=45)
        native('PATCH', 'container/' + container_id, {'privileged': 'true'})
        subprocess.run([common[0], 'app-install-verify'] + common[1:] + ['-review', str(review)],
            check=True, stdout=subprocess.DEVNULL, timeout=45)
        report['staged_installation'] = {'native_plan_verify': True, 'manual_exact_privilege_verified': True}
        nat = native('PUT', 'ip/firewall/nat', {'chain': 'dstnat', 'action': 'dst-nat', 'protocol': 'tcp',
            'src-address': '10.0.2.2/32', 'dst-address': '10.0.2.15', 'dst-port': '18446', 'to-addresses': ip,
            'to-ports': '8443', 'comment': 'mikrocentauri:app6:nat:management'})['.id']; owned.append(('ip/firewall/nat', nat))
        with socket.socket(socket.AF_UNIX) as monitor:
            monitor.connect(str(work / 'monitor')); monitor.recv(4096)
            monitor.sendall(b'hostfwd_add wan tcp:127.0.0.1:18446-:18446\n'); monitor.recv(4096)
        tls = ssl.create_default_context(cafile=str(app_cert)); tls.minimum_version = ssl.TLSVersion.TLSv1_3
        native('PATCH', 'app/' + app_id, {'disabled': 'false'})
        settle(lambda: api('POST', '/auth/login', {'password': password})[0] == 200, 'TLS login')
        _, logged = api('POST', '/auth/login', {'password': password}); token = logged['access_token']

        def ready():
            status, body = api('GET', '/health/ready')
            return status == 200 and body.get('ready')

        try:
            settle(ready, 'native readiness', 120)
        except AssertionError:
            for command in ('/bin/ps', '/sbin/ip route show table all', '/bin/cat /proc/1/status'):
                captured = subprocess.run(['ssh', '-p', '22336', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=accept-new', '-o',
                    'UserKnownHostsFile=' + str(private / 'known_hosts'), 'admin+ct@127.0.0.1',
                    '/container/shell app-' + name + ' cmd="' + command + '"'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
                print(command, captured.stdout.decode(), flush=True)
            raise

        settle(lambda: core().get('healthy') == 'true', 'production image healthcheck')
        assert not core().get('entrypoint') and not core().get('cmd')
        report['production_entrypoint'] = {'default_go_launcher': True, 'native_ready': True, 'healthy': True}
        settle(lambda: any(r.get('list') == 'mc-app6-up-lease' and r.get('address') == '192.168.88.0/24'
            for r in native('GET', 'ip/firewall/address-list')), 'native observer UP lease')
        settle(lambda: all(r.get('disabled') == 'false' for path in ('ip/route', 'ip/firewall/nat')
            for r in native('GET', path) if r.get('comment') in
            ('mikrocentauri:app6:route:fakeip', 'mikrocentauri:app6:nat:dns-tcp', 'mikrocentauri:app6:nat:dns-udp')),
            'native steering enabled')
        native('POST', 'ip/dns/cache/flush', {})
        packets = {}
        for domain, peer in [('selected.test', '10.77.0.10'), ('unselected.test', '10.77.0.1')]:
            tcp = request(domain, path='/app6-native'); assert_success(tcp, peer)
            h3 = quic(domain, tcp['resolved_ipv4']); assert h3['remote_ip'] == peer
            udp = marked_udp(domain)
            packets[domain] = {'expected_peer': peer, 'tcp': tcp, 'udp': udp, 'http3': h3}
        report['packets'] = packets
        baseline = packets['selected.test']['tcp']['resolved_ipv4']
        native('PATCH', 'app/' + app_id, {'disabled': 'true'}); settle(stopped, 'native stop')
        settle(lambda: not any(r.get('list') == 'mc-app6-up-lease' for r in native('GET', 'ip/firewall/address-list')), 'lease withdrawal')
        down = workload('selected.test', domain='selected.test', address=baseline); assert_success(down, '10.77.0.1')
        native('PATCH', 'app/' + app_id, {'disabled': 'false'})
        settle(lambda: api('POST', '/auth/login', {'password': password})[0] == 200, 'restart login')
        _, logged = api('POST', '/auth/login', {'password': password}); token = logged['access_token']
        settle(ready, 'restart readiness')
        settle(lambda: any(r.get('list') == 'mc-app6-up-lease' for r in native('GET', 'ip/firewall/address-list')), 'restart UP lease')
        cached = workload('unselected.test', domain='selected.test', address=baseline); assert_success(cached, '10.77.0.10')
        report['native_restart'] = {'lease_withdrawn': True, 'cached_down_direct': down, 'cached_up_proxy': cached,
            'auth_preserved': True, 'namespace_preserved': True}
        # Preserve an admitted FakeIP generation through real binary image changes.
        snapshot_dir = private / name; snapshot_dir.mkdir(mode=0o700)
        swap = AppSwap(native, lambda fn: settle(fn, 'volume replacement'), app_id,
            disk, name, 22336, snapshot_dir, cache_path='runtime/transitions/engine-cache.db')
        swap.backup()
        transitions = []
        for label, desc, image_manifest in [('previous-native', rollback_descriptor, rollback_manifest),
                                          ('final-native', descriptor, manifest)]:
            remote_image = 'https://10.0.2.2:18539/mikrocentauri@' + desc['digest']
            proof = swap.replace(composition, remote_image, privileged=False)
            app_id = proof['app_id']; container_id = proof['container_id']
            assert app()['ip-address'] == ip
            stage_review = private / (name + '-' + label + '-review.json')
            subprocess.run([common[0], 'app-install-plan'] + common[1:] + ['-app', name,
                '-image-ref', remote_image, '-image-config-sha256', image_manifest['config']['digest'],
                '-out', str(stage_review)], check=True, stdout=subprocess.DEVNULL, timeout=45)
            native('PATCH', 'container/' + container_id, {'privileged': 'true'})
            subprocess.run([common[0], 'app-install-verify'] + common[1:] + ['-review', str(stage_review)],
                check=True, stdout=subprocess.DEVNULL, timeout=45)
            native('PATCH', 'app/' + app_id, {'disabled': 'false'})
            settle(lambda: api('POST', '/auth/login', {'password': password})[0] == 200, 'image replacement login')
            _, logged = api('POST', '/auth/login', {'password': password}); token = logged['access_token']
            settle(ready, 'image replacement native readiness')
            settle(lambda: any(r.get('list') == 'mc-app6-up-lease' for r in native('GET', 'ip/firewall/address-list')), 'replacement UP lease')
            settle(lambda: core().get('healthy') == 'true', 'image default health after replacement')
            assert core().get('image-id') == image_manifest['config']['digest'][7:]
            assert not core().get('entrypoint') and not core().get('cmd') and not core().get('healthcheck-cmd')
            tcp = workload('unselected.test', domain='selected.test', address=baseline); assert_success(tcp, '10.77.0.10')
            h3 = quic('selected.test', baseline); assert h3['remote_ip'] == '10.77.0.10'
            udp = marked_udp('selected.test')
            assert udp['resolved_ipv4'] == baseline
            transitions.append({'stage': label, 'manifest': desc['digest'],
                'config': image_manifest['config']['digest'], 'restored_original_bytes': proof,
                'native_ready': True, 'default_healthcheck': True, 'cached_tcp': tcp,
                'cached_http3': h3, 'udp': udp, 'expected_peer': '10.77.0.10', 'auth_preserved': True})
        report['native_image_replacement'] = transitions
        report['accepted'] = True
        report['completed'] = True
    finally:
        if app_id:
            native('PATCH', 'app/' + app_id, {'disabled': 'true'})
            if core() and core().get('image-id'):
                settle(stopped, 'final stop')
        for path, object_id in reversed(owned): native('DELETE', path + '/' + object_id)
        # Runtime publication creates reserved mappings beyond the static fixture IDs.
        for path in ('ip/firewall/nat', 'ip/route', 'tool/netwatch', 'system/scheduler', 'ip/firewall/address-list'):
            for row in native('GET', path):
                if row.get('comment', '').startswith('mikrocentauri:app6:'):
                    native('DELETE', path + '/' + row['.id'])
        if controller_user: native('DELETE', 'user/' + controller_user)
        server.shutdown(); server.server_close()
        report['cleanup'] = {'app_disabled': bool(app_id), 'owned_native_objects_removed': True, 'data_preserved': True}
        (work / 'native-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
