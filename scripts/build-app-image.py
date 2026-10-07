#!/usr/bin/env python3
"""Build pinned multi-platform OCI layout and RouterOS Docker archives without Docker.

No registry writes, user configuration, credentials or laboratory files enter an
image. All downloaded inputs are checksum verified before packaging. Layer and
JSON encoding is deterministic; Go build VCS/time metadata is excluded.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OCI = 'application/vnd.oci.'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def asset(spec, cache):
    path = cache / spec['sha256']
    if not path.exists():
        with urllib.request.urlopen(spec['url'], timeout=60) as response:
            data = response.read(256 << 20)
        if digest(data) != spec['sha256']:
            raise ValueError('download checksum mismatch')
        path.write_bytes(data)
    data = path.read_bytes()
    if digest(data) != spec['sha256']:
        raise ValueError('cached input checksum mismatch')
    return data


def elf(data, arch):
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != {'amd64': 62, 'arm64': 183}[arch]:
        raise ValueError('binary architecture mismatch')


def normalized_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe archive path')
    return str(path).removeprefix('./').rstrip('/')


def add_bytes(archive, name, data, mode=0o644):
    entry = tarfile.TarInfo(name)
    entry.mode, entry.size = mode, len(data)
    archive.addfile(entry, io.BytesIO(data))


def make_layer(rootfs, additions):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as target:
        with tarfile.open(fileobj=io.BytesIO(rootfs), mode='r:gz') as source:
            seen = set()
            for member in sorted(source.getmembers(), key=lambda x: x.name):
                name = normalized_name(member.name)
                if name in {'.', ''}:
                    continue
                if name in seen or name in additions:
                    raise ValueError('duplicate or overridden base path')
                seen.add(name)
                if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                    raise ValueError('unsupported base archive entry')
                if member.islnk():
                    normalized_name(member.linkname)
                member.name = name
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                member.pax_headers = {}
                target.addfile(member, source.extractfile(member) if member.isfile() else None)
        for name, (data, mode) in sorted(additions.items()):
            normalized_name(name)
            add_bytes(target, name, data, mode)
        for name, mode in [('data', 0o700), ('data/bootstrap', 0o700), ('dev/net', 0o755)]:
            if name in seen:
                continue
            entry = tarfile.TarInfo(name)
            entry.type, entry.mode = tarfile.DIRTYPE, mode
            target.addfile(entry)
    return output.getvalue()


def descriptor(kind, data, **extra):
    return {'mediaType': OCI + kind, 'digest': 'sha256:' + digest(data), 'size': len(data), **extra}


def blob(layout, data):
    (layout / 'blobs/sha256' / digest(data)).write_bytes(data)


def build_platform(arch, lock, cache, out, layout, go):
    inputs = lock['platforms'][arch]
    rootfs = asset(inputs['rootfs'], cache)
    sb_archive = asset(inputs['sing_box'], cache)
    with tarfile.open(fileobj=io.BytesIO(sb_archive), mode='r:gz') as archive:
        candidates = [m for m in archive.getmembers() if m.isfile() and PurePosixPath(m.name).name == 'sing-box']
        if len(candidates) != 1:
            raise ValueError('ambiguous engine archive')
        sb = archive.extractfile(candidates[0]).read()
    binary_path = out / ('mikrocentauri-' + arch)
    subprocess.run([go, 'build', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(binary_path), './cmd/mikrocentauri'],
                   cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0'), check=True)
    binary = binary_path.read_bytes()
    elf(binary, arch)
    elf(sb, arch)
    notices = (ROOT / 'THIRD_PARTY_NOTICES.md').read_bytes()
    layer = make_layer(rootfs, {
        'usr/bin/mikrocentauri': (binary, 0o755),
        'usr/bin/sing-box': (sb, 0o755),
        'usr/share/mikrocentauri/THIRD_PARTY_NOTICES.md': (notices, 0o644),
        'usr/share/mikrocentauri/LICENSE': ((ROOT / 'LICENSE').read_bytes(), 0o644),
        'usr/share/mikrocentauri/sing-box-LICENSE': (asset(lock['license'], cache), 0o644),
    })
    compressed = gzip.compress(layer, mtime=0)
    config = encode({'architecture': arch, 'os': 'linux', 'config': {
        'Entrypoint': ['/usr/bin/mikrocentauri', 'app-run', '-config', '/data/bootstrap/app.json'],
        'WorkingDir': '/', 'Env': ['PATH=/usr/bin:/bin:/usr/sbin:/sbin'],
        'Volumes': {'/data': {}}, 'ExposedPorts': {'8443/tcp': {}},
        'StopSignal': 'SIGTERM',
        'Healthcheck': {'Test': ['CMD', '/usr/bin/mikrocentauri', 'app-health', '-config', '/data/bootstrap/app.json'],
                        'Interval': 30000000000, 'Timeout': 5000000000, 'Retries': 3},
    }, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + digest(layer)]}})
    manifest = encode({'schemaVersion': 2, 'mediaType': OCI + 'image.manifest.v1+json',
                       'config': descriptor('image.config.v1+json', config),
                       'layers': [descriptor('image.layer.v1.tar+gzip', compressed)]})
    for data in [compressed, config, manifest]:
        blob(layout, data)
    docker_name = digest(config) + '.json'
    docker_manifest = encode([{'Config': docker_name, 'RepoTags': ['mikrocentauri:phase6-' + arch], 'Layers': ['layer/layer.tar']}])
    docker_path = out / ('mikrocentauri-' + arch + '.tar')
    with tarfile.open(docker_path, 'w') as archive:
        for name, data in [(docker_name, config), ('manifest.json', docker_manifest), ('layer/layer.tar', layer)]:
            add_bytes(archive, name, data)
    return descriptor('image.manifest.v1+json', manifest, platform={'architecture': arch, 'os': 'linux'}), {
        'manifest_digest': 'sha256:' + digest(manifest), 'archive_sha256': digest(docker_path.read_bytes()),
        'compressed_layer_bytes': len(compressed), 'uncompressed_layer_bytes': len(layer),
        'controller_sha256': digest(binary), 'engine_sha256': digest(sb), 'inputs': inputs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/app-image')
    parser.add_argument('--go', default=str(ROOT / '.cache/go/bin/go'))
    args = parser.parse_args()
    toolchain = json.loads((ROOT / 'toolchain.lock.json').read_text())
    go_version = subprocess.check_output([args.go, 'version'], text=True).strip()
    if go_version.split()[2] != 'go' + toolchain['go_version']:
        raise ValueError('Go version does not match toolchain.lock.json')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    cache = ROOT / '.cache/app-image-assets'
    cache.mkdir(parents=True, exist_ok=True)
    layout = out / 'oci'
    (layout / 'blobs/sha256').mkdir(parents=True, exist_ok=True)
    lock = json.loads((ROOT / 'packaging/image-assets.lock.json').read_text())
    manifests, platforms = [], {}
    for arch in ['amd64', 'arm64']:
        entry, evidence = build_platform(arch, lock, cache, out, layout, args.go)
        manifests.append(entry)
        platforms[arch] = evidence
        print(arch, evidence['manifest_digest'], flush=True)
    index = encode({'schemaVersion': 2, 'mediaType': OCI + 'image.index.v1+json', 'manifests': manifests})
    (layout / 'index.json').write_bytes(index)
    (layout / 'oci-layout').write_bytes(encode({'imageLayoutVersion': '1.0.0'}))
    evidence = {'schema': 1, 'go_version': toolchain['go_version'], 'index_digest': 'sha256:' + digest(index), 'platforms': platforms,
                'entrypoint': 'app-run', 'volume': '/data', 'registry_published': False,
                'runtime_acceptance': 'not implied by image construction'}
    (out / 'build.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('multi-platform index', evidence['index_digest'])


if __name__ == '__main__':
    main()
