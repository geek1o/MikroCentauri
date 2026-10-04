#!/usr/bin/env python3
"""Build a local docker-save archive without Docker; RouterOS import is a separate test."""
import argparse,hashlib,io,json,pathlib,tarfile,subprocess,os
p=argparse.ArgumentParser();p.add_argument('--go',default='go');p.add_argument('--arch',choices=['amd64','arm64'],default='amd64');p.add_argument('--out',default='.cache/probe-image.tar');a=p.parse_args();root=pathlib.Path(__file__).resolve().parents[1];dest=(root/a.out).resolve();dest.parent.mkdir(parents=True,exist_ok=True)
binary=dest.parent/'mc-probe';env=dict(os.environ,GOOS='linux',GOARCH=a.arch,CGO_ENABLED='0');subprocess.run([a.go,'build','-trimpath','-ldflags=-s -w','-o',str(binary),'./lab/probe'],cwd=root,env=env,check=True)
layer=io.BytesIO()
with tarfile.open(fileobj=layer,mode='w') as t:
 for directory in ['dev','dev/net','proc','sys']:
  info=tarfile.TarInfo(directory);info.type=tarfile.DIRTYPE;info.mode=0o755;t.addfile(info)
 info=tarfile.TarInfo('probe');b=binary.read_bytes();info.size=len(b);info.mode=0o755;t.addfile(info,io.BytesIO(b))
b=layer.getvalue();digest=hashlib.sha256(b).hexdigest();cfg=json.dumps({'architecture':a.arch,'os':'linux','config':{'Entrypoint':['/probe'],'WorkingDir':'/'},'rootfs':{'type':'layers','diff_ids':['sha256:'+digest]}}).encode();cfgname=hashlib.sha256(cfg).hexdigest()+'.json';manifest=json.dumps([{'Config':cfgname,'RepoTags':['mikrocentauri-probe:local'],'Layers':['layer/layer.tar']}]).encode()
with tarfile.open(dest,'w') as t:
 for name,data in [(cfgname,cfg),('manifest.json',manifest),('layer/layer.tar',b)]:
  info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;t.addfile(info,io.BytesIO(data))
print(str(dest));print('sha256',hashlib.sha256(dest.read_bytes()).hexdigest())
