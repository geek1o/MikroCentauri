#!/usr/bin/env python3
"""Verify the local OCI graph and RouterOS archives without a container daemon."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(out):
    layout = out / 'oci'
    evidence = json.loads((out / 'build.json').read_text())
    index_data = (layout / 'index.json').read_bytes()
    assert evidence['index_digest'] == 'sha256:' + sha(index_data)
    assert json.loads((layout / 'oci-layout').read_text()) == {'imageLayoutVersion': '1.0.0'}
    index = json.loads(index_data)
    assert len(index['manifests']) == 2
    assert {m['platform']['architecture'] for m in index['manifests']} == {'amd64', 'arm64'}

    def read(entry):
        kind, digest = entry['digest'].split(':')
        assert kind == 'sha256' and len(digest) == 64
        data = (layout / 'blobs/sha256' / digest).read_bytes()
        assert len(data) == entry['size'] and sha(data) == digest
        return data

    for entry in index['manifests']:
        arch = entry['platform']['architecture']
        manifest = json.loads(read(entry))
        assert evidence['platforms'][arch]['manifest_digest'] == entry['digest']
        config_data = read(manifest['config'])
        config = json.loads(config_data)
        assert config['architecture'] == arch and config['os'] == 'linux'
        settings = config['config']
        assert settings['Entrypoint'] == ['/usr/bin/mikrocentauri', 'app-run', '-config', '/data/bootstrap/app.json']
        assert settings['Volumes'] == {'/data': {}} and settings['StopSignal'] == 'SIGTERM'
        assert settings['Env'] == ['PATH=/usr/bin:/bin:/usr/sbin:/sbin']
        assert settings['Healthcheck']['Test'][2] == 'app-health'
        assert len(manifest['layers']) == 1
        layer = gzip.decompress(read(manifest['layers'][0]))
        assert config['rootfs']['diff_ids'] == ['sha256:' + sha(layer)]
        with tarfile.open(fileobj=io.BytesIO(layer)) as archive:
            names = archive.getnames()
            assert len(names) == len(set(names))
            assert not any('..' in Path(n).parts or n.startswith('/') for n in names)
            assert not any(n.startswith(('data/', 'run/secrets/')) and archive.getmember(n).isfile() for n in names)
            assert not any(n.startswith(('lab/', '.cache/')) or n.endswith(('.key', 'model.json', 'router.json', 'auth.json')) for n in names)
            assert archive.getmember('data').mode == 0o700
            for name, key in [('usr/bin/mikrocentauri', 'controller_sha256'), ('usr/bin/sing-box', 'engine_sha256')]:
                member = archive.getmember(name)
                data = archive.extractfile(member).read()
                assert member.mode == 0o755 and data[:6] == b'\x7fELF\x02\x01'
                assert struct.unpack_from('<H', data, 18)[0] == {'amd64': 62, 'arm64': 183}[arch]
                assert sha(data) == evidence['platforms'][arch][key]
            assert archive.getmember('etc/ssl/certs/ca-certificates.crt').size > 0
            assert archive.getmember('sbin/ip').issym()
            assert archive.getmember('usr/share/mikrocentauri/sing-box-LICENSE').size > 0
        docker_path = out / ('mikrocentauri-' + arch + '.tar')
        assert sha(docker_path.read_bytes()) == evidence['platforms'][arch]['archive_sha256']
        with tarfile.open(docker_path) as archive:
            docker = json.load(archive.extractfile('manifest.json'))[0]
            assert archive.extractfile(docker['Config']).read() == config_data
            assert archive.extractfile(docker['Layers'][0]).read() == layer
        print(arch + ': OCI digests, ELF architecture, archive and secret-free image verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/app-image')
    verify(parser.parse_args().out.resolve())
