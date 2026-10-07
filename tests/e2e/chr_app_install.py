#!/usr/bin/env python3
"""App management TLS and persistent-volume restart fixture on a separate CHR clone.

This does not provision native dataplane privileges or exercise proxy packets.
All credentials are synthetic; no secret/private key/bearer value is reported.
"""
import argparse, base64, copy, datetime, hashlib, http.client, http.server, ipaddress, json
import pathlib, re, socket, ssl, subprocess, tempfile, threading, time, urllib.error, urllib.request, uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oci', type=pathlib.Path, default=pathlib.Path('.cache/app-image/oci'))
    parser.add_argument('--image-updates', action='store_true',
        help='exercise stopped-backup/recreate/restore A/B/A with immutable distinct digests')
    parser.add_argument('--expected-ip', default='', help='optional isolated first-free App IP, asserted after allocation')
    parser.add_argument('--candidate-oci', type=pathlib.Path)
    parser.add_argument('--public-origin', default='')
    parser.add_argument('--browser-node', help='optional Node executable for real Chromium management check')
    parser.add_argument('--ssh-port', type=int, default=22326)
    parser.add_argument('--port', type=int, default=18326)
    parser.add_argument('--monitor', type=pathlib.Path, default=pathlib.Path('.cache/app-schema/monitor'))
    parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('.cache/app-schema/install-results.json'))
    args = parser.parse_args()
    assert args.port != 18080 and 1024 <= args.port <= 65535
    if args.public_origin:
        assert args.public_origin == 'https://127.0.0.1:18443'
    authorization = 'Basic ' + base64.b64encode(b'admin:').decode()

    def native(method, path, body=None):
        req = urllib.request.Request(f'http://127.0.0.1:{args.port}/rest/' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': authorization, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=90) as response:
                data = response.read()
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'Native {method} {path}: HTTP {error.code}') from None

    def sync_clone_clock():
        # TCG can lose wall time during extraction; keep TLS validity meaningful.
        now = datetime.datetime.now(datetime.timezone.utc)
        native('POST', 'system/clock/set', {'time-zone-autodetect': 'false',
            'time-zone-name': 'Etc/UTC', 'date': now.strftime('%Y-%m-%d'),
            'time': now.strftime('%H:%M:%S')})

    def settle(predicate, timeout=240):
        deadline = time.monotonic() + timeout
        last = None
        synced = 0
        while time.monotonic() < deadline:
            if time.monotonic() - synced > 10:
                sync_clone_clock()
                synced = time.monotonic()
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, RuntimeError, AssertionError, urllib.error.URLError) as error:
                last = type(error).__name__
            time.sleep(.5)
        raise AssertionError('Native installation fixture did not settle: ' + str(last))

    sync_clone_clock()
    resource = native('GET', 'system/resource')
    assert resource['version'] == '7.24.5 (stable)' and resource['board-name'].startswith('CHR ')
    run_id = uuid.uuid4().hex[:8]
    name = 'mc-install-' + run_id
    blobs = {}

    def load_image(layout):
        layout = layout.resolve()
        index = json.loads((layout / 'index.json').read_text())
        descriptor = next(m for m in index['manifests'] if m['platform']['architecture'] == 'amd64')
        raw = (layout / 'blobs/sha256' / descriptor['digest'][7:]).read_bytes()
        manifest = json.loads(raw)
        blobs[descriptor['digest']] = raw
        for entry in [manifest['config']] + manifest['layers']:
            data = (layout / 'blobs/sha256' / entry['digest'][7:]).read_bytes()
            assert 'sha256:' + hashlib.sha256(data).hexdigest() == entry['digest']
            blobs[entry['digest']] = data
        return descriptor['digest'], manifest

    digest_a, manifest_a = load_image(args.oci)
    if args.candidate_oci:
        digest_b, manifest_b = load_image(args.candidate_oci)
        variant = 'separate supplied OCI candidate; binary/version equivalence not inferred'
    else:
        manifest_b = copy.deepcopy(manifest_a)
        config = json.loads(blobs[manifest_a['config']['digest']])
        config['config'].setdefault('Labels', {})['mikrocentauri.lab.packaging-variant'] = run_id
        raw = json.dumps(config, separators=(',', ':'), sort_keys=True).encode()
        config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        blobs[config_digest] = raw
        manifest_b['config'].update(digest=config_digest, size=len(raw))
        raw = json.dumps(manifest_b, separators=(',', ':'), sort_keys=True).encode()
        digest_b = 'sha256:' + hashlib.sha256(raw).hexdigest()
        blobs[digest_b] = raw
        variant = 'metadata-only OCI config label; identical executable and filesystem layer'
    assert digest_a != digest_b
    report = {'routeros': resource['version'], 'scope': 'native App management/persistence; no proxy dataplane',
              'images': {'A': digest_a, 'B': digest_b, 'candidate_scope': variant},
              'public_origin': args.public_origin or 'internal exact Host via verified TLS socket',
              'stages': [], 'clock': 'isolated TCG clone synchronized to UTC wall time during TLS waits'}
    created_app = None
    owned_nat = None
    servers = []
    with tempfile.TemporaryDirectory(prefix='mc-app-install-') as private_path:
        private = pathlib.Path(private_path)
        registry_cert, registry_key = private / 'registry.crt', private / 'registry.key'

        def certificate(cert, key, san):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '2', '-subj', '/CN=fixture',
                '-addext', 'subjectAltName=' + san], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        certificate(registry_cert, registry_key, 'IP:10.0.2.2')
        public_registry_cert = registry_cert.read_bytes()

        class Registry(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path == '/v2/':
                    raw, content_type = b'{}', 'application/json'
                else:
                    match = re.fullmatch(r'/v2/mikrocentauri/(manifests|blobs)/(sha256:[a-f0-9]{64})', self.path)
                    if not match or match[2] not in blobs:
                        self.send_error(404)
                        return
                    raw = blobs[match[2]]
                    content_type = ('application/octet-stream' if match[1] == 'blobs'
                                    else json.loads(raw)['mediaType'])
                self.send_response(200)
                for key, value in {'Content-Type': content_type, 'Content-Length': str(len(raw)),
                    'Docker-Distribution-Api-Version': 'registry/2.0',
                    'Docker-Content-Digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

        class Certificate(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path != '/registry.crt':
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(public_registry_cert)))
                self.end_headers()
                self.wfile.write(public_registry_cert)

        registry = http.server.ThreadingHTTPServer(('127.0.0.1', 18529), Registry)
        registry.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(registry_cert, registry_key)
        registry.socket = context.wrap_socket(registry.socket, server_side=True)
        servers = [registry, http.server.ThreadingHTTPServer(('127.0.0.1', 18530), Certificate)]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

        def app():
            return native('GET', 'app/' + created_app)

        def core():
            return next((c for c in native('GET', 'container') if c.get('interface') == app().get('interface')
                         and c.get('name') == 'app-' + name), None)

        def forward_management(destination):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
                monitor.connect(str(args.monitor)); monitor.settimeout(.2)
                for command in (None, 'hostfwd_remove wan tcp:127.0.0.1:18443',
                        'hostfwd_add wan tcp:127.0.0.1:18443-' + destination + ':8443'):
                    if command:
                        monitor.sendall((command + '\n').encode())
                    try:
                        while monitor.recv(4096):
                            pass
                    except TimeoutError:
                        pass

        try:
            disk = next(d for d in native('GET', 'disk') if d.get('mounted') == 'true' and d.get('fs') == 'ext4')
            native('POST', 'app/settings/set', {'disk': disk['slot'], 'lan-bridge': 'bridge-lan',
                                             'router-ip': '192.168.88.1'})
            cert_name = name + '.crt'
            native('POST', 'tool/fetch', {'url': 'http://10.0.2.2:18530/registry.crt', 'dst-path': cert_name})
            native('POST', 'certificate/import', {'file-name': cert_name, 'passphrase': ''})
            trust = next(c for c in native('GET', 'certificate') if c.get('name', '').startswith(cert_name))
            native('PATCH', 'certificate/' + trust['.id'], {'trusted': 'true'})
            image_a = 'https://10.0.2.2:18529/mikrocentauri@' + digest_a
            composition = {'name': name, 'services': {'core': {'image': image_a,
                'ports': ['8443:8443:api-secure'], 'volumes': ['state:/data']}}, 'volumes': {'state': None}}
            # Seed the first YAML before any App command override exists.
            # This fixed clone address is asserted against native allocation.
            used = {r.get('address', '').split('/')[0] for r in native('GET', 'interface/veth')}
            assigned = args.expected_ip or next('172.18.0.' + str(i) for i in range(2, 255)
                if '172.18.0.' + str(i) not in used)
            assert ipaddress.IPv4Address(assigned).is_private
            app_cert, app_key = private / 'app.crt', private / 'app.key'
            certificate(app_cert, app_key, 'IP:' + assigned + ',IP:127.0.0.1')
            endpoint = {'enabled': False, 'id': '', 'name': '', 'protocol': 'vless',
                        'server': '127.0.0.1', 'port': 9, 'uuid': 'bf000d23-0752-40b4-affe-68f7707a9661', 'tls': False}
            endpoint['id'] = hashlib.sha256(json.dumps(endpoint, separators=(',', ':')).encode()).hexdigest()
            endpoint['enabled'], endpoint['name'] = True, 'Unreachable fixture only'
            model = {'schema_version': 2, 'instance': 'app-install', 'mode': 'hybrid', 'endpoints': [endpoint],
                'groups': [], 'rules': [], 'default_outbound': 'direct',
                'dns': {'bootstrap': '1.1.1.1', 'fakeip_range': '198.19.0.0/16', 'cache_path': '/data/runtime/cache.db'}}
            password = 'DisposableAppInstallOnly-' + uuid.uuid4().hex
            settings = {'schema_version': 1, 'data_directory': '/data', 'listen': assigned + ':8443',
                'allow_clients': ['10.0.2.2/32'], 'tls_cert': '/data/bootstrap/server.crt',
                'tls_key': '/data/bootstrap/server.key', 'model': '/data/bootstrap/model.json',
                'password_file': '/data/bootstrap/password'}
            if args.public_origin:
                settings['public_origin'] = args.public_origin
            cache_config = {'log': {'disabled': True}, 'experimental': {'cache_file': {
                'enabled': True, 'path': '/data/runtime/cache.db', 'store_fakeip': True}},
                'inbounds': [{'type': 'mixed', 'tag': 'fixture', 'listen': '127.0.0.1', 'listen_port': 10999}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
            inputs = {'app.json': json.dumps(settings), 'model.json': json.dumps(model),
                'server.crt': app_cert.read_text(), 'server.key': app_key.read_text(), 'password': password,
                'cache-init.json': json.dumps(cache_config)}
            command = ('-c "umask 077; mkdir -p /data/bootstrap /data/runtime /data/proof; '
                'chmod 0700 /data /data/bootstrap /data/runtime /data/proof; '
                'if [ ! -f /data/bootstrap/app.json ]; then cp /fixture-input/* /data/bootstrap/; '
                'chmod 0600 /data/bootstrap/*; fi; if [ ! -f /data/runtime/cache.db ]; then '
                'timeout -s TERM 2 /usr/bin/sing-box run -c /data/bootstrap/cache-init.json; fi; '
                'sha256sum /data/api/auth.json /data/bootstrap/model.json /data/api/draft.json '
                '/data/api/preferences.json /data/runtime/cache.db > /data/proof/hashes 2>/dev/null; '
                '(/sbin/ip -o link; /sbin/ip rule show; /sbin/ip route show table all; '
                'cat /proc/sys/net/ipv4/ip_forward; ls -l /dev/net/tun) > /data/proof/platform 2>&1; '
                'exec /usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json"')
            inputs['install.sh'] = command[4:-1]
            composition['services']['core'].update(entrypoint='/bin/sh', command='/fixture-input/install.sh',
                configs=[{'source': 'input' + str(i), 'target': '/fixture-input/' + filename, 'mode': '0600'}
                         for i, filename in enumerate(inputs)],
                healthcheck={'test': ['CMD', '/bin/sh', '-c',
                    'sha256sum /data/api/auth.json /data/bootstrap/model.json '
                    '/data/api/draft.json /data/api/preferences.json /data/runtime/cache.db '
                    '> /data/proof/hashes 2>/dev/null; '
                    'exec /usr/bin/mikrocentauri app-health -config /data/bootstrap/app.json'],
                    'interval': '2s', 'timeout': '5s', 'retries': 1})
            composition['configs'] = {'input' + str(i): {'content': value} for i, value in enumerate(inputs.values())}
            created_app = native('PUT', 'app', {'yaml': json.dumps(composition),
                'disabled': 'true', 'use-https': 'false'})['.id']
            native('PATCH', 'app/' + created_app, {'disabled': 'false'})
            assert settle(lambda: app().get('ip-address')) == assigned
            settle(lambda: (c if (c := core()) and c.get('healthy') == 'true' else None))
            assert app()['ip-address'] == assigned
            report['discovered'] = {'ip': assigned, 'veth': app()['interface'],
                'state_directory': f"{disk['slot']}/apps/{name}/state", 'default_network': app()['default-network']}
            # QEMU sends the fixture socket to the router's own LAN address,
            # allowing the App's generated DNAT to be tested first.
            forward_management('192.168.88.1')
            tls = ssl.create_default_context(cafile=str(app_cert)); tls.minimum_version = ssl.TLSVersion.TLSv1_3
            advertised_host = '127.0.0.1:18443' if args.public_origin else assigned + ':8443'
            token = None

            def api(method, path, body=None, host=None, authenticated=True, origin=None):
                conn = http.client.HTTPSConnection('127.0.0.1', 18443, context=tls, timeout=8)
                if not args.public_origin:
                    conn.sock = tls.wrap_socket(socket.create_connection(('127.0.0.1', 18443), 8), server_hostname=assigned)
                headers = {'Host': host or advertised_host, 'Content-Type': 'application/json'}
                if authenticated and token:
                    headers['Authorization'] = 'Bearer ' + token
                if origin:
                    headers['Origin'] = origin
                conn.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=headers)
                response = conn.getresponse(); raw = response.read(); version = conn.sock.version() if conn.sock else 'TLSv1.3'
                result = response.status, raw, dict(response.headers), version
                conn.close(); return result

            auto_mapping = [{k: r[k] for k in ('chain', 'action', 'protocol', 'dst-address', 'dst-port',
                'in-interface', 'src-address', 'to-addresses', 'to-ports') if k in r}
                for r in native('GET', 'ip/firewall/nat') if r.get('to-addresses') == assigned]
            report['automatic_port_mappings'] = auto_mapping
            try:
                automatic = api('GET', '/api/v1/health/live', authenticated=False)[0] == 200
            except (OSError, ssl.SSLError, http.client.HTTPException):
                automatic = False
            report['automatic_management_reachable'] = automatic
            if not automatic:
                # slirp's WAN peer can reach the guest WAN IP; LAN ARP is
                # unavailable without a connected LAN fixture client.
                forward_management('10.0.2.15')
                owned_nat = native('PUT', 'ip/firewall/nat', {'chain': 'dstnat', 'action': 'dst-nat',
                    'protocol': 'tcp', 'src-address': '10.0.2.2/32', 'dst-address': '10.0.2.15',
                    'dst-port': '8443', 'to-addresses': assigned, 'to-ports': '8443',
                    'comment': 'mikrocentauri:app-install:' + run_id})['.id']
                report['explicit_management_rule'] = 'clone-only DNAT; source 10.0.2.2/32 and WAN destination 10.0.2.15:8443; automatic LAN mapping not admitted'
            settle(lambda: api('GET', '/api/v1/health/live', authenticated=False)[0] == 200)
            assert api('GET', '/', authenticated=False)[0] == 200
            assert api('GET', '/', host='wrong.invalid:8443', authenticated=False)[0] == 403
            assert api('GET', '/api/v1/system', authenticated=False)[0] == 401
            assert api('GET', '/api/v1/health/ready', authenticated=False)[0] == 401
            status, raw, _, version = api('POST', '/api/v1/auth/login', {'password': password}, authenticated=False)
            assert status == 200
            token = json.loads(raw)['access_token']
            assert api('GET', '/api/v1/system')[0] == 200
            assert api('GET', '/api/v1/health/ready')[0] == 503
            if args.browser_node:
                assert args.public_origin
                browser = subprocess.run([args.browser_node, 'tests/e2e/webui/app-install.mjs'],
                    input=json.dumps({'url': args.public_origin, 'password': password}), text=True,
                    stdout=subprocess.PIPE, check=True, timeout=90)
                report['browser'] = json.loads(browser.stdout)
            assert api('GET', '/api/v1/system', origin='https://wrong.invalid')[0] == 403
            _, raw, _, _ = api('GET', '/api/v1/config')
            view = json.loads(raw)
            draft_policy = view['policy']
            draft_policy['rules'] = [{'id': 'persisted-lab-rule', 'domains': ['retained.invalid'], 'outbound': 'direct'}]
            assert api('POST', '/api/v1/config/draft/policy', {'draft_revision': view.get('draft_revision', 0),
                'mode': view['model']['mode'], 'groups': view['model']['groups'], 'policy': draft_policy})[0] == 200
            assert api('POST', '/api/v1/preferences', {'language': 'ru', 'theme': 'dark', 'time_zone': 'Europe/Moscow'})[0] == 200
            report['management'] = {'ui_http_status': 200, 'login_http_status': 200, 'protected_api_http_status': 200,
                'wrong_host_http_status': 403, 'wrong_origin_http_status': 403, 'unauthenticated_http_status': 401,
                'runtime_ready_http_status': 503, 'tls_version': version, 'private_socket_clients': ['10.0.2.2/32']}

            def disable():
                native('PATCH', 'app/' + created_app, {'disabled': 'true'})
                settle(lambda: (c := core()) is None or c.get('stopped') == 'true')

            def hashes():
                rows = native('POST', 'file/read', {'file': f"{disk['slot']}/apps/{name}/state/proof/hashes",
                                                    'offset': '0', 'chunk-size': '2048'})
                raw = ''.join(r.get('data', '') for r in rows)
                result = dict((line.split()[1], line.split()[0]) for line in raw.splitlines())
                assert set(result) == {'/data/api/auth.json', '/data/bootstrap/model.json', '/data/api/draft.json',
                                       '/data/api/preferences.json', '/data/runtime/cache.db'}
                return result

            disable()
            snapshot = private / 'volume-backup'
            snapshot.mkdir(mode=0o700)
            scp = ['scp', '-pr', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                   '-o', 'UserKnownHostsFile=/dev/null', '-P', str(args.ssh_port)]
            remote_state = f"admin@127.0.0.1:{disk['slot']}/apps/{name}/state"
            subprocess.run(scp + [remote_state, str(snapshot)], check=True, timeout=90,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for path in (snapshot / 'state').rglob('*'):
                path.chmod(0o700 if path.is_dir() else 0o600)
            (snapshot / 'state').chmod(0o700)
            baseline = {'/data/' + path: hashlib.sha256((snapshot / 'state' / path).read_bytes()).hexdigest()
                for path in ('api/auth.json', 'bootstrap/model.json', 'api/draft.json',
                             'api/preferences.json', 'runtime/cache.db')}

            repair = snapshot / 'state' / 'bootstrap' / 'permission-repair.sh'
            repair.write_text('set -eu\nfind /data -type d -exec chmod 0700 {} +\n'
                'find /data -type f -exec chmod 0600 {} +\n'
                'printf repaired > /data/proof/permissions-repaired\n'
                'chmod 0600 /data/proof/permissions-repaired\n')
            repair.chmod(0o600)

            def restore_volume():
                for directory in (f"{disk['slot']}/apps/{name}", f"{disk['slot']}/apps/{name}/state"):
                    native('POST', 'file/add', {'name': directory, 'type': 'directory'})
                subprocess.run(scp + [str(snapshot / 'state') + '/.',
                    f"admin@127.0.0.1:{disk['slot']}/apps/{name}/state"], check=True, timeout=90,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # RouterOS SFTP accepts -p but drops private Unix modes.
                # Materialize the generated production container, then repair
                # permissions in a bounded one-shot helper while App is disabled.
                native('PATCH', 'app/' + created_app, {'disabled': 'false'})
                settle(lambda: (c := core()) and c.get('image-id') and c.get('stopped') == 'true')
                disable()
                container_id = core()['.id']
                native('PATCH', 'container/' + container_id, {'entrypoint': '/bin/sh',
                    'cmd': '/data/bootstrap/permission-repair.sh'})
                native('POST', 'container/start', {'.id': container_id})
                settle(lambda: native('POST', 'file/read', {'file':
                    f"{disk['slot']}/apps/{name}/state/proof/permissions-repaired",
                    'offset': '0', 'chunk-size': '64'}))
                settle(lambda: core().get('stopped') == 'true')
                native('PATCH', 'container/' + container_id, {'entrypoint': '', 'cmd': ''})

            def remove_record():
                old_interface = app().get('interface', '')
                native('DELETE', 'app/' + created_app)
                if old_interface:
                    settle(lambda: not any(v.get('name') == old_interface for v in native('GET', 'interface/veth')))

            composition['services']['core'].pop('entrypoint')
            composition['services']['core'].pop('command')
            composition['services']['core'].pop('configs')
            composition.pop('configs')
            remove_record()
            created_app = native('PUT', 'app', {'yaml': json.dumps(composition),
                'disabled': 'true', 'use-https': 'false'})['.id']
            stages = [('A-restart-1', digest_a, manifest_a), ('A-restart-2', digest_a, manifest_a)]
            if args.image_updates:
                stages = [('A', digest_a, manifest_a), ('B', digest_b, manifest_b), ('A-rollback', digest_a, manifest_a)]
            for label, digest, manifest in stages:
                print('native image stage ' + label, flush=True)
                disable()
                if args.image_updates:
                    composition['services']['core']['image'] = 'https://10.0.2.2:18529/mikrocentauri@' + digest
                    remove_record()
                    created_app = native('PUT', 'app', {'yaml': json.dumps(composition),
                        'disabled': 'true', 'use-https': 'false'})['.id']
                    settle(lambda: digest[7:] in app().get('container-command-lines', ''))
                if args.image_updates or label == 'A-restart-1':
                    restore_volume()
                native('PATCH', 'app/' + created_app, {'disabled': 'false'})
                settle(lambda: (c if (c := core()) and c.get('healthy') == 'true'
                               and c.get('image-id') == manifest['config']['digest'][7:] else None))
                assert app()['ip-address'] == assigned
                assert core().get('entrypoint', '') == '' and core().get('cmd', '') == ''
                current = hashes()
                assert current == baseline
                status, raw, _, _ = api('POST', '/api/v1/auth/login', {'password': password}, authenticated=False)
                assert status == 200
                token = json.loads(raw)['access_token']
                status, raw, _, _ = api('GET', '/api/v1/config/draft')
                assert status == 200 and 'persisted-lab-rule' in raw.decode()
                assert api('GET', '/api/v1/health/ready', authenticated=False)[0] == 401
                assert api('GET', '/api/v1/health/ready')[0] == 503
                report['stages'].append({'image': label, 'actual_manifest': digest,
                    'actual_config_digest': manifest['config']['digest'], 'healthy': True,
                    'persistent_auth_model_draft_preferences_cache_bytes_equal': True,
                    'stable_ip': assigned, 'ui_reachable': api('GET', '/')[0] == 200})
            disable()
            # Comparison stages used a fixture hash probe. Admit the actual
            # image healthcheck separately, with all native overrides cleared.
            composition['services']['core'].pop('healthcheck')
            remove_record()
            created_app = native('PUT', 'app', {'yaml': json.dumps(composition),
                'disabled': 'true', 'use-https': 'false'})['.id']
            restore_volume()
            native('PATCH', 'app/' + created_app, {'disabled': 'false'})
            health_started = time.monotonic()
            settle(lambda: time.monotonic() - health_started > 35 and core().get('healthy') == 'true')
            assert core().get('healthcheck-cmd', '') == ''
            assert core()['default-healthcheck-cmd'] == 'CMD,/usr/bin/mikrocentauri,app-health,-config,/data/bootstrap/app.json'
            report['production_healthcheck'] = {'comparison_stages_fixture_hash_override': True,
                'final_native_override_empty': True, 'image_default_app_health': True,
                'default_interval': '30s', 'healthy_after_full_interval': True}
            disable()
            report['production_entrypoint'] = {'default_go_entrypoint_running': True,
                'fixture_shell_executes_production_go_launcher': False,
                'fixture_config_mounts_retained': False}
            report['update_workflow'] = 'private binary-safe stopped-volume SFTP backup, remove App record, recreate same name with exact immutable image, restore volume, enable'
            report['image_update_admitted'] = bool(args.image_updates)
            report['images']['B_exercised'] = bool(args.image_updates)
            bundle = args.output.parent / 'install-bundle' / 'bootstrap'
            bundle.mkdir(parents=True, exist_ok=True)
            bundle.chmod(0o700); bundle.parent.chmod(0o700)
            for filename in ('app.json', 'model.json', 'server.crt', 'server.key', 'password'):
                path = bundle / filename; path.write_text(inputs[filename]); path.chmod(0o600)
            report['cache_scope'] = 'valid empty sing-box BoltDB initialized once; no admitted FakeIP alias/state migration proof'
            report['policy_scope'] = 'durable edited draft; no native dataplane apply'
        finally:
            if created_app:
                native('PATCH', 'app/' + created_app, {'disabled': 'true'})
            if owned_nat:
                native('DELETE', 'ip/firewall/nat/' + owned_nat)
            for server in servers:
                server.shutdown(); server.server_close()
            if created_app:
                report['cleanup'] = {'app_disabled': app()['disabled'] == 'true', 'data_preserved': True,
                    'app_cleanup_used': False, 'temporary_management_rule_removed': owned_nat is not None,
                    'temporary_management_rule_created': owned_nat is not None}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
