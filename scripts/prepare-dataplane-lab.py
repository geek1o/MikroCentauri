#!/usr/bin/env python3
"""Prepare pinned Linux VMs/gateway fixtures, without starting or changing a router."""
import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[1]
CACHE=ROOT/'.cache'
OUT=CACHE/'dataplane'
OUT.mkdir(parents=True,exist_ok=True)
GO=str(CACHE/'go/bin/go')
SB=str(CACHE/'sing-box-1.14.2-darwin-arm64/sing-box')
# Host validator path comes from the same platform mapping as bootstrap-tools.py.
import platform
arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
SB=str(CACHE/f'sing-box-1.14.2-{platform.system().lower()}-{arch}/sing-box')
lock=json.loads((ROOT/'lab/linux/assets.lock.json').read_text())
asset=lock['sing_box_musl'];archive=CACHE/asset['url'].rsplit('/',1)[1]
if not archive.exists():urllib.request.urlretrieve(asset['url'],archive)
if hashlib.sha256(archive.read_bytes()).hexdigest()!=asset['sha256']:raise SystemExit('Linux musl checksum mismatch')
with tarfile.open(archive) as tar:tar.extractall(CACHE,filter='data')
env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
subprocess.run([GO,'build','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',str(OUT/'mc-lab'),'./lab/workload'],cwd=ROOT,env=env,check=True)
subprocess.run([GO,'build','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',str(OUT/'mc-quic'),'.'],cwd=ROOT/'lab/quic',env=env,check=True)
config=json.loads((ROOT/'lab/configs/hybrid.json').read_text())
config['vless_uri']='vless://bf000d23-0752-40b4-affe-68f7707a9661@10.77.0.10:8443?type=tcp&security=none'
config['dns_upstream']='10.77.0.20'
(OUT/'app.json').write_text(json.dumps(config,indent=2)+'\n')
subprocess.run([GO,'run','./cmd/mikrocentauri','generate','-config',str(OUT/'app.json'),'-out',str(OUT/'gateway.json'),'-sing-box',SB],cwd=ROOT,check=True)
gateway=json.loads((OUT/'gateway.json').read_text());gateway['log']={'level':'info','timestamp':True}
(OUT/'gateway.json').write_text(json.dumps(gateway,indent=2)+'\n');os.chmod(OUT/'gateway.json',0o600)
payload=OUT/'payload';payload.mkdir(exist_ok=True)
import shutil
for src,name in [(CACHE/'sing-box-1.14.2-linux-amd64-musl/sing-box','sing-box'),(ROOT/'lab/configs/proxy-server.json','server.json'),(OUT/'mc-quic','mc-quic')]:shutil.copy2(src,payload/name)
subprocess.run(['python3','scripts/build-linux-lab.py','--binary',str(OUT/'mc-lab'),'--payload-dir',str(payload)],cwd=ROOT,check=True)
subprocess.run(['python3','scripts/build-gateway-lab.py','--config',str(OUT/'gateway.json')],cwd=ROOT,check=True)
