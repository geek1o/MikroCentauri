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
p.add_argument('--dynamic-dns', action='store_true', help='Explicit isolated dynamic-publication fixture')
a = p.parse_args()
out = pathlib.Path(a.out).resolve()
out.parent.mkdir(parents=True, exist_ok=True)
config_path = pathlib.Path(a.config)
if a.dynamic_dns:
    # Derive the entire fixed lab fixture, not merely its environment switch.
    candidate = json.loads(config_path.read_text())
    dns_in = [i for i in candidate['inbounds'] if i.get('tag') == 'dns-in']
    if len(dns_in) != 1:
        raise SystemExit('Dynamic lab requires one dns-in listener')
    dns_in[0]['listen'] = '127.0.0.1'
    dns_in[0]['listen_port'] = 5354
    explicit = [i for i in candidate['inbounds'] if i.get('tag') == 'explicit-in']
    if len(explicit) != 1:
        raise SystemExit('Dynamic lab requires one loopback canary listener')
    explicit[0]['listen'] = '127.0.0.1'
    explicit[0]['listen_port'] = 2080
    for rules in [candidate['dns']['rules'], candidate['route']['rules']]:
        for rule in rules:
            if 'selected.test' in rule.get('domain', []):
                rule['domain'] = ['selected.test', 'second.test', 'third.test']
    config_path = out.parent / 'gateway-dynamic.json'
    config_path.write_text(json.dumps(candidate, indent=2)+'\n')
    os.chmod(config_path, 0o600)
binary = out.parent / 'mc-gateway'
subprocess.run([a.go, 'build', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(binary), './lab/gateway'], cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'), check=True)
tool = out.parent / 'mc-generation-tool'
if a.dynamic_dns:
    subprocess.run([a.go, 'build', '-buildvcs=false', '-trimpath', '-ldflags=-s -w', '-o', str(tool), './lab/generationtool'], cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'), check=True)
rootfs = ROOT / '.cache/linux-lab/rootfs.tar.gz'
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
    files = [('bin/mc-gateway', binary, 0o755), ('bin/sing-box', ROOT / '.cache/sing-box-1.14.2-linux-amd64-musl/sing-box', 0o755), ('data/singbox.json', config_path, 0o600)]
    if a.dynamic_dns:
        files.append(('bin/mc-generation-tool', tool, 0o755))
    for name, path, mode in files:
        data = path.read_bytes()
        member = tarfile.TarInfo(name)
        member.mode = mode
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
blob = layer.getvalue()
env = ['MC_INTERFACE=mc-probe']
if a.dynamic_dns:
    env += ['MC_DYNAMIC_DNS=1', 'MC_SELECTED_DOMAINS=selected.test,second.test,third.test']
config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {'Entrypoint': ['/bin/mc-gateway'], 'Env': env, 'WorkingDir': '/'}, 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(blob).hexdigest()]}}).encode()
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
