#!/usr/bin/env python3
"""Disabled App schema probes against the separate, disposable localhost CHR.

The default probes disabled YAML admission without image pulls or starts. The
explicit --runtime-oci mode uses a local TLS registry and synthetic inputs on
the separate clone. No /app cleanup, shared lab port or production target.
"""
import argparse
import base64
import json
import pathlib
import hashlib
import http.server
import re
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18326)
    parser.add_argument('--output', type=pathlib.Path,
                        default=pathlib.Path('.cache/app-schema/import-results.json'))
    parser.add_argument('--runtime-oci', type=pathlib.Path,
                        help='Optional actual image layout; run generated-container probes on the clone')
    args = parser.parse_args()
    if args.port == 18080 or not 1024 <= args.port <= 65535:
        parser.error('Use a separate disposable clone management port')
    base = f'http://127.0.0.1:{args.port}/rest/'
    authorization = 'Basic ' + base64.b64encode(b'admin:').decode()

    def request(method, path, body=None):
        req = urllib.request.Request(base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': authorization, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    status, resource = request('GET', 'system/resource')
    assert status == 200 and resource['board-name'].startswith('CHR ')
    assert resource['version'] == '7.24.5 (stable)', resource['version']
    variants = {
        'baseline': '',
        'privileged': '    privileged: true\n',
        'cap_add': '    cap_add: [NET_ADMIN]\n',
        'unknown_field': '    mikrocentauri_invented_field: true\n',
        'devices': '    devices: ["/dev/net/tun:/dev/net/tun"]\n',
        'healthcheck': ('    healthcheck:\n      test: ["CMD", "true"]\n'
                        '      interval: 30s\n      timeout: 5s\n      retries: 3\n'),
        'secrets': '    secrets: [admin_password]\n',
    }
    report = {'routeros': resource['version'], 'board': resource['board-name'],
              'scope': 'disabled YAML admission only; no image pull or runtime proof',
              'probes': {}}
    created = []
    run_id = uuid.uuid4().hex[:8]
    try:
        for label, extra in variants.items():
            name = f'mc-schema-{run_id}-{label}'
            # Intentionally unavailable immutable image. Apps stay disabled.
            yaml = (f'name: {name}\nsupported-archs: [x86]\nservices:\n  core:\n'
                    '    image: docker.io/library/alpine@sha256:' + '0' * 64 + '\n'
                    '    environment:\n      MC_ROUTER: "[routerIP]"\n'
                    '    ports: ["9443:8443:api-secure"]\n'
                    '    volumes: ["state:/var/lib/mikrocentauri"]\n' + extra +
                    '    restart: unless-stopped\nvolumes:\n  state:\n')
            if label == 'secrets':
                yaml += 'secrets:\n  admin_password:\n'
            code, row = request('PUT', 'app', {'yaml': yaml, 'disabled': 'true'})
            if code == 201:
                created.append(row['.id'])
                assert row['disabled'] == 'true' and row['running'] == 'false'
            safe = {key: row[key] for key in (
                'disabled', 'running', 'devices', 'required-hw-devices',
                'required-mounts', 'firewall-redirects', 'default-network',
                'error', 'message', 'detail') if key in row}
            report['probes'][label] = {'http_status': code, 'projection': safe}
        assert all(p['http_status'] == 201 for p in report['probes'].values()), report
        report['interpretation'] = ('Unknown fields also accepted: admission does not '
                                    'prove privileged/cap_add translation or healthcheck/secrets execution.')
    finally:
        for app_id in reversed(created):
            code, _ = request('DELETE', 'app/' + app_id)
            assert code in (200, 204), 'Could not remove disabled schema probe'
    report['cleanup'] = {'disabled_probe_records_removed': len(created), 'app_cleanup_used': False}
    if args.runtime_oci:
        report['runtime'] = runtime_probe(request, args.runtime_oci.resolve(), run_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


def runtime_probe(request, layout, run_id):
    """Serve only immutable local blobs and a temporary public fixture certificate."""
    index = json.loads((layout / 'index.json').read_text())
    manifest_digest = next(m['digest'] for m in index['manifests']
                           if m['platform']['architecture'] == 'amd64')
    blobs = layout / 'blobs/sha256'
    manifest = json.loads((blobs / manifest_digest[7:]).read_text())
    allowed = {manifest_digest, manifest['config']['digest']} | {l['digest'] for l in manifest['layers']}
    evidence = {'scope': 'generated-container fixture; not production installation readiness',
                'manifest_digest': manifest_digest, 'containers': {}}
    apps = []

    def wait_for(predicate, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(.5)
        raise AssertionError('Native App fixture did not settle')

    def container_row(name):
        return next((c for c in request('GET', 'container')[1]
                     if c.get('name') == 'app-' + name and c.get('arch') == 'amd64'), None)

    with tempfile.TemporaryDirectory(prefix='mc-app-registry-') as private_dir:
        private = pathlib.Path(private_dir)
        cert, key = private / 'registry.crt', private / 'registry.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '2',
                        '-subj', '/CN=10.0.2.2', '-addext', 'subjectAltName=IP:10.0.2.2'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public_certificate = cert.read_bytes()

        class Registry(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path == '/v2/':
                    data, content_type = b'{}', 'application/json'
                else:
                    match = re.fullmatch(r'/v2/mikrocentauri/(manifests|blobs)/(sha256:[a-f0-9]{64})', self.path)
                    if not match or match[2] not in allowed:
                        self.send_error(404)
                        return
                    data = (blobs / match[2][7:]).read_bytes()
                    assert 'sha256:' + hashlib.sha256(data).hexdigest() == match[2]
                    content_type = ('application/octet-stream' if match[1] == 'blobs'
                                    else json.loads(data)['mediaType'])
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Docker-Distribution-Api-Version', 'registry/2.0')
                self.send_header('Docker-Content-Digest', 'sha256:' + hashlib.sha256(data).hexdigest())
                self.end_headers()
                self.wfile.write(data)

        class PublicCertificate(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path != '/registry.crt':
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(public_certificate)))
                self.end_headers()
                self.wfile.write(public_certificate)

        registry = http.server.ThreadingHTTPServer(('127.0.0.1', 18529), Registry)
        registry.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        registry.socket = context.wrap_socket(registry.socket, server_side=True)
        certificates = http.server.ThreadingHTTPServer(('127.0.0.1', 18530), PublicCertificate)
        for server in (registry, certificates):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            disks = request('GET', 'disk')[1]
            disk = next(d for d in disks if d.get('mounted') == 'true' and d.get('fs') == 'ext4')
            code, _ = request('POST', 'app/settings/set', {'disk': disk['slot'],
                              'lan-bridge': 'bridge-lan', 'router-ip': '192.168.88.1'})
            assert code == 200
            cert_name = f'mc-schema-{run_id}.crt'
            assert request('POST', 'tool/fetch', {'url': 'http://10.0.2.2:18530/registry.crt',
                                                'dst-path': cert_name})[0] == 200
            assert request('POST', 'certificate/import', {'file-name': cert_name, 'passphrase': ''})[0] == 200
            certificate = next(c for c in request('GET', 'certificate')[1]
                               if c.get('name', '').startswith(cert_name))
            assert request('PATCH', 'certificate/' + certificate['.id'], {'trusted': 'true'})[0] == 200
            image = 'https://10.0.2.2:18529/mikrocentauri@' + manifest_digest
            for label, extra in [('baseline', ''), ('privileged', '    privileged: true\n'),
                                 ('cap_add', '    cap_add: [NET_ADMIN]\n')]:
                name = f'mc-p6-{run_id}-{label}'
                yaml = f'name: {name}\nservices:\n  core:\n    image: {image}\n' + extra
                code, app = request('PUT', 'app', {'yaml': yaml, 'disabled': 'true', 'use-https': 'false'})
                assert code == 201
                apps.append(app['.id'])
                assert request('PATCH', 'app/' + app['.id'], {'disabled': 'false'})[0] == 200
                row = wait_for(lambda: container_row(name))
                wait_for(lambda: container_row(name).get('stopped') == 'true')
                row = container_row(name)
                assert row['privileged'] == 'false'
                evidence['containers'][label] = {k: row[k] for k in (
                    'privileged', 'restart-policy', 'default-entrypoint', 'image-id',
                    'stopped', 'check-certificate') if k in row}
                if label == 'baseline':
                    assert request('PATCH', 'container/' + row['.id'], {'logging': 'true'})[0] == 200
                    assert request('POST', 'container/start', {'.id': row['.id']})[0] == 200
                    wait_for(lambda: container_row(name).get('stopped') == 'true')
                    messages = request('GET', 'log')[1]
                    assert any(('app-' + name + ':') in log.get('message', '')
                               and 'invalid private app settings' in log.get('message', '')
                               for log in messages)
                    evidence['containers'][label]['startup_failure'] = 'invalid private app settings'
                assert request('PATCH', 'app/' + app['.id'], {'disabled': 'true'})[0] == 200
            # A fixture entrypoint examines metadata only; secret bytes never leave the container.
            name = f'mc-p6-{run_id}-files'
            command = ('-c "mkdir -p /data/proof; stat -c %a:%u:%g:%s /run/secrets/admin_password '
                       '> /data/proof/secret-metadata; if [ -f /data/proof/marker ]; then '
                       'echo existing > /data/proof/persistence; else echo fixture > /data/proof/marker; '
                       'echo created > /data/proof/persistence; fi; sleep 600"')
            yaml = (f'name: {name}\nservices:\n  core:\n    image: {image}\n'
                    '    entrypoint: /bin/sh\n    command: ' + command + '\n'
                    '    volumes: ["state:/data"]\n    secrets: [admin_password]\n'
                    '    healthcheck:\n      test: ["CMD", "true"]\n      interval: 2s\n'
                    '      timeout: 1s\n      retries: 1\nvolumes:\n  state:\nsecrets:\n  admin_password:\n')
            code, app = request('PUT', 'app', {'yaml': yaml, 'disabled': 'true', 'use-https': 'false'})
            assert code == 201
            apps.append(app['.id'])
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'false'})[0] == 200
            row = wait_for(lambda: (c if (c := container_row(name)) and c.get('healthy') == 'true' else None))
            state_path = f"{disk['slot']}/apps/{name}/state/proof/"

            def read_proof(filename):
                code, rows = request('POST', 'file/read', {'file': state_path + filename,
                                                        'offset': '0', 'chunk-size': '128'})
                assert code == 200
                return ''.join(r.get('data', '') for r in rows).strip()

            first = read_proof('persistence')
            metadata = read_proof('secret-metadata')
            assert re.fullmatch(r'444:0:0:[1-9][0-9]*', metadata), metadata
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'true'})[0] == 200
            wait_for(lambda: container_row(name).get('stopped') == 'true')
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'false'})[0] == 200
            wait_for(lambda: (c if (c := container_row(name)) and c.get('healthy') == 'true' else None))
            wait_for(lambda: read_proof('persistence') == 'existing')
            evidence['files'] = {'secret_metadata': metadata, 'first_marker_state': first,
                                 'marker_after_stop_start': 'existing', 'healthcheck_status': 'good',
                                 'secret_value_read_or_reported': False}
            # Production executable and its own strict HTTPS liveness probe,
            # with synthetic inputs. No RouterOS profile or packet steering.
            app_cert, app_key = private / 'app.crt', private / 'app.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(app_key), '-out', str(app_cert), '-days', '2',
                            '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            endpoint = {'enabled': False, 'id': '', 'name': '', 'protocol': 'vless',
                        'server': '127.0.0.1', 'port': 9,
                        'uuid': 'bf000d23-0752-40b4-affe-68f7707a9661', 'tls': False}
            endpoint['id'] = hashlib.sha256(json.dumps(endpoint, separators=(',', ':')).encode()).hexdigest()
            endpoint['enabled'], endpoint['name'] = True, 'Unreachable fixture only'
            model = {'schema_version': 2, 'instance': 'app-lab', 'mode': 'hybrid',
                     'endpoints': [endpoint], 'groups': [], 'rules': [], 'default_outbound': 'direct',
                     'dns': {'bootstrap': '1.1.1.1', 'fakeip_range': '198.19.0.0/16',
                             'cache_path': '/data/runtime/cache.db'}}
            settings = {'schema_version': 1, 'data_directory': '/data', 'listen': '127.0.0.1:8443',
                        'allow_clients': [], 'tls_cert': '/data/bootstrap/server.crt',
                        'tls_key': '/data/bootstrap/server.key', 'model': '/data/bootstrap/model.json',
                        'password_file': '/data/bootstrap/password'}
            inputs = {'app.json': json.dumps(settings), 'model.json': json.dumps(model),
                      'server.crt': app_cert.read_text(), 'server.key': app_key.read_text(),
                      'password': 'DisposableAppLabOnly-' + uuid.uuid4().hex}
            name = f'mc-p6-{run_id}-api'
            composition = {'name': name, 'services': {'core': {
                'image': image, 'entrypoint': '/bin/sh',
                'command': '-c "umask 077; mkdir -p /data/bootstrap; chmod 0700 /data /data/bootstrap; '
                           'cp /fixture-input/* /data/bootstrap/; chmod 0600 /data/bootstrap/*; '
                           'exec /usr/bin/mikrocentauri app-run -config /data/bootstrap/app.json"',
                'volumes': ['state:/data'],
                'configs': [{'source': 'input' + str(i), 'target': '/fixture-input/' + filename,
                             'mode': '0600'} for i, filename in enumerate(inputs)],
                'healthcheck': {'test': ['CMD', '/usr/bin/mikrocentauri', 'app-health', '-config',
                                         '/data/bootstrap/app.json'], 'interval': '2s',
                                'timeout': '5s', 'retries': 1}}},
                'volumes': {'state': None}, 'configs': {
                    'input' + str(i): {'content': content} for i, content in enumerate(inputs.values())}}
            code, app = request('PUT', 'app', {'yaml': json.dumps(composition),
                                             'disabled': 'true', 'use-https': 'false'})
            assert code == 201
            apps.append(app['.id'])
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'false'})[0] == 200
            wait_for(lambda: (c if (c := container_row(name)) and c.get('healthy') == 'true' else None))
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'true'})[0] == 200
            wait_for(lambda: container_row(name).get('stopped') == 'true')
            assert request('PATCH', 'app/' + app['.id'], {'disabled': 'false'})[0] == 200
            wait_for(lambda: (c if (c := container_row(name)) and c.get('healthy') == 'true' else None))
            evidence['api_only'] = {'production_app_run_started': True,
                                    'strict_tls13_app_health_passed': True,
                                    'healthy_after_stop_start': True,
                                    'runtime_profile_supplied': False, 'packet_steering_tested': False,
                                    'management_exposure': 'container loopback only',
                                    'fixtures': 'synthetic private bootstrap inputs; no user credentials'}
        finally:
            for app_id in reversed(apps):
                request('PATCH', 'app/' + app_id, {'disabled': 'true'})
            for server in (registry, certificates):
                server.shutdown()
                server.server_close()
    evidence['cleanup'] = {'apps_disabled': len(apps), 'data_retained': True, 'app_cleanup_used': False}
    return evidence


if __name__ == '__main__':
    main()
