#!/usr/bin/env python3
"""Package the isolated CHR dataplane spike; not a production application image."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--go', default=str(ROOT / '.cache/go/bin/go'))
p.add_argument('--config', default=str(ROOT / '.cache/dataplane/gateway.json'))
p.add_argument('--out', default=str(ROOT / '.cache/dataplane/gateway-image.tar'))
a = p.parse_args()
out = pathlib.Path(a.out).resolve()
out.parent.mkdir(parents=True, exist_ok=True)
binary = out.parent / 'mc-gateway'
subprocess.run([a.go, 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary), './lab/gateway'], cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'), check=True)
rootfs = ROOT / '.cache/alpine-minirootfs.tar.gz'
assert hashlib.sha256(rootfs.read_bytes()).hexdigest() == 'c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677'
layer = io.BytesIO()
with tarfile.open(fileobj=layer, mode='w') as archive:
    with tarfile.open(rootfs) as alpine:
        for member in alpine:
            archive.addfile(member, alpine.extractfile(member) if member.isfile() else None)
    for directory in ['data', 'dev/net']:
        member = tarfile.TarInfo(directory)
        member.type = tarfile.DIRTYPE
        member.mode = 0o755
        archive.addfile(member)
    for name, path, mode in [('bin/mc-gateway', binary, 0o755), ('bin/sing-box', ROOT / '.cache/sing-box-1.14.2-linux-amd64-musl/sing-box', 0o755), ('data/singbox.json', pathlib.Path(a.config), 0o600)]:
        data = path.read_bytes()
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
blob = layer.getvalue()
config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {'Entrypoint': ['/bin/mc-gateway'], 'Env': ['MC_INTERFACE=mc-probe'], 'WorkingDir': '/'}, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(blob).hexdigest()]}}).encode()
name = hashlib.sha256(config).hexdigest() + '.json'
manifest = json.dumps([{'Config': name, 'RepoTags': ['mikrocentauri-gateway:lab'], 'Layers': ['layer/layer.tar']}]).encode()
with tarfile.open(out, 'w') as archive:
    for filename, data in [(name, config), ('manifest.json', manifest), ('layer/layer.tar', blob)]:
        member = tarfile.TarInfo(filename)
        member.size = len(data)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(data))
print(str(out))
print('sha256', hashlib.sha256(out.read_bytes()).hexdigest())
