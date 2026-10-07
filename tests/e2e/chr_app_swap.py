"""Disposable CHR-only App backup/recreate/restore helper. REST callback returns decoded JSON."""
import copy, hashlib, json, pathlib, subprocess

class AppSwap:
    def __init__(self, rest, settle, app_id, disk, name, ssh_port, private_directory, cache_path="runtime/cache.db"):
        assert ssh_port not in (22, 22222) and 1024 <= ssh_port <= 65535
        self.rest, self.settle, self.app_id = rest, settle, app_id
        self.disk, self.name = disk, name
        assert cache_path in ("runtime/cache.db", "runtime/transitions/engine-cache.db")
        self.cache_path = cache_path
        self.snapshot = pathlib.Path(private_directory) / 'swap-backup'
        self.snapshot.mkdir(mode=0o700)
        self.scp = ['scp', '-pr', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null', '-P', str(ssh_port)]

    def app(self):
        return self.rest('GET', 'app/' + self.app_id)

    def core(self):
        a = self.app()
        return next((c for c in self.rest('GET', 'container') if c.get('name') == 'app-' + self.name
                     and c.get('interface') == a.get('interface')), None)

    def stopped(self):
        self.rest('PATCH', 'app/' + self.app_id, {'disabled': 'true'})
        self.settle(lambda: (c := self.core()) is None or c.get('stopped') == 'true')

    def backup(self):
        self.stopped()
        remote = f'admin@127.0.0.1:{self.disk}/apps/{self.name}/state'
        subprocess.run(self.scp + [remote, str(self.snapshot)], check=True, timeout=90,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = self.snapshot / 'state'
        for p in [state] + list(state.rglob('*')):
            assert not p.is_symlink(), 'Snapshot must not contain symlinks'
            p.chmod(0o700 if p.is_dir() else 0o600)
        self.hashes = {str(p.relative_to(state)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in state.rglob('*') if p.is_file()}
        assert {'bootstrap/app.json', 'api/auth.json', self.cache_path} <= self.hashes.keys()
        repair = state / 'bootstrap' / 'permission-repair.sh'
        repair.write_text('set -eu\nmkdir -p /data/proof\n'
            'find /data -type d -exec chmod 0700 {} +\n'
            'find /data -type f -exec chmod 0600 {} +\n'
            'sha256sum /data/' + self.cache_path + ' > /data/proof/cache-before-start\n'
            'printf repaired > /data/proof/permissions-repaired\n'
            'chmod 0600 /data/proof/cache-before-start /data/proof/permissions-repaired\n'
            'rm /data/bootstrap/permission-repair.sh\n')
        repair.chmod(0o600)

    def replace(self, composition, immutable_image, privileged=False):
        """Restores original backup; leaves App disabled, generated container stopped.

        Caller must perform its exact image/profile/privilege verification before enabling.
        FakeIP alias/packet proof remains the caller's responsibility after startup.
        """
        assert hasattr(self, 'hashes'), 'Complete private stopped backup required before removal'
        assert immutable_image.startswith('https://') and '@sha256:' in immutable_image
        self.stopped()
        old_interface = self.app().get('interface', '')
        self.rest('DELETE', 'app/' + self.app_id)
        if old_interface:
            self.settle(lambda: not any(v.get('name') == old_interface for v in self.rest('GET', 'interface/veth')))
        composition = copy.deepcopy(composition)
        core = composition['services']['core']
        core['image'] = immutable_image
        core.pop('entrypoint', None); core.pop('command', None)
        self.app_id = self.rest('PUT', 'app', {'yaml': json.dumps(composition), 'disabled': 'true',
                                             'use-https': 'false'})['.id']
        for directory in (f'{self.disk}/apps/{self.name}', f'{self.disk}/apps/{self.name}/state'):
            self.rest('POST', 'file/add', {'name': directory, 'type': 'directory'})
        subprocess.run(self.scp + [str(self.snapshot / 'state') + '/.',
            f'admin@127.0.0.1:{self.disk}/apps/{self.name}/state'], check=True, timeout=90,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # SFTP loses Unix private modes; first production start denies private settings.
        self.rest('PATCH', 'app/' + self.app_id, {'disabled': 'false'})
        self.settle(lambda: (c := self.core()) and c.get('image-id') and c.get('stopped') == 'true')
        self.stopped()
        container_id = self.core()['.id']
        self.rest('PATCH', 'container/' + container_id, {'entrypoint': '/bin/sh',
                                                       'cmd': '/data/bootstrap/permission-repair.sh'})
        self.rest('POST', 'container/start', {'.id': container_id})
        self.settle(lambda: self.rest('POST', 'file/read', {'file':
            f'{self.disk}/apps/{self.name}/state/proof/permissions-repaired', 'offset': '0', 'chunk-size': '64'}))
        self.settle(lambda: self.core().get('stopped') == 'true')
        self.rest('PATCH', 'container/' + container_id, {'entrypoint': '', 'cmd': ''})
        if privileged:
            self.rest('PATCH', 'container/' + container_id, {'privileged': 'true'})
        rows = self.rest('POST', 'file/read', {'file':
            f'{self.disk}/apps/{self.name}/state/proof/cache-before-start', 'offset': '0', 'chunk-size': '256'})
        digest = ''.join(r['data'] for r in rows).split()[0]
        assert digest == self.hashes[self.cache_path], 'Restored cache must equal stopped original before startup'
        verification = self.snapshot / ('verify-' + self.app_id.replace('*', ''))
        verification.mkdir(mode=0o700)
        subprocess.run(self.scp + [f'admin@127.0.0.1:{self.disk}/apps/{self.name}/state',
            str(verification)], check=True, timeout=90, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        restored = verification / 'state'
        for path, digest in self.hashes.items():
            assert hashlib.sha256((restored / path).read_bytes()).hexdigest() == digest
        for p in [restored] + list(restored.rglob('*')):
            assert not p.is_symlink()
            p.chmod(0o700 if p.is_dir() else 0o600)
        assert self.core().get('remote-image') == immutable_image
        return {'app_id': self.app_id, 'container_id': container_id,
                'cache_bytes_equal_before_start': True, 'all_original_files_equal_before_start': True, 'stopped': True}
