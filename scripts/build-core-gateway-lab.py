#!/usr/bin/env python3
"""Build a separate disposable CHR image exercising the production core owner.

This builder never rewrites the legacy gateway image, root directory or config.
Public fixture credentials are confined to lab/coregateway; not deployment defaults.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROOTFS_SHA256 = 'c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--go', default=str(ROOT / '.cache/go/bin/go'))
p.add_argument('--out', default=str(ROOT / '.cache/core-native/coregateway-image.tar'))
a = p.parse_args()
out = pathlib.Path(a.out).resolve()
out.parent.mkdir(parents=True, exist_ok=True)
binary = out.parent / 'mc-coregateway'
subprocess.run([a.go, 'build', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(binary), './lab/coregateway'], cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'), check=True)
rootfs = ROOT / '.cache/linux-lab/rootfs.tar.gz'
if hashlib.sha256(rootfs.read_bytes()).hexdigest() != ROOTFS_SHA256:
    raise SystemExit('Alpine fixture rootfs digest mismatch')
sing_box = ROOT / '.cache/sing-box-1.14.2-linux-amd64-musl/sing-box'
layer = io.BytesIO()
with tarfile.open(fileobj=layer, mode='w') as archive:
    with tarfile.open(rootfs) as alpine:
        for member in alpine:
            archive.addfile(member, alpine.extractfile(member) if member.isfile() else None)
    for directory, mode in [('data', 0o700), ('data/core-v3', 0o700), ('dev/net', 0o755)]:
        member = tarfile.TarInfo(directory)
        member.type = tarfile.DIRTYPE
        member.mode = mode
        archive.addfile(member)
    for name, path in [('bin/mc-coregateway', binary), ('bin/sing-box', sing_box)]:
        data = path.read_bytes()
        member = tarfile.TarInfo(name)
        member.mode = 0o755
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
blob = layer.getvalue()
config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {'Entrypoint': ['/bin/mc-coregateway'], 'Env': ['MC_CORE_LAB=1'], 'WorkingDir': '/'}, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(blob).hexdigest()]}}).encode()
name = hashlib.sha256(config).hexdigest() + '.json'
manifest = json.dumps([{'Config': name, 'RepoTags': ['mikrocentauri-coregateway:lab'], 'Layers': ['layer/layer.tar']}]).encode()
with tarfile.open(out, 'w') as archive:
    for filename, data in [(name, config), ('manifest.json', manifest), ('layer/layer.tar', blob)]:
        member = tarfile.TarInfo(filename)
        member.size = len(data)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(data))
metadata = {'image_sha256': hashlib.sha256(out.read_bytes()).hexdigest(), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'sing_box_sha256': hashlib.sha256(sing_box.read_bytes()).hexdigest(), 'rootfs_sha256': ROOTFS_SHA256, 'pool': '198.19.0.0/16', 'state_directory': '/data/core-v3'}
out.with_suffix('.metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
print(str(out))
print('sha256', metadata['image_sha256'])
