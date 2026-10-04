#!/usr/bin/env python3
"""Local verified tools only; never install globally or silently advance pins."""
import hashlib,json,pathlib,platform,tarfile,urllib.request
root=pathlib.Path(__file__).resolve().parents[1];lock=json.loads((root/'toolchain.lock.json').read_text());arch={'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine());key=platform.system().lower()+'-'+str(arch)
if key not in lock['platforms']:raise SystemExit('Unsupported host tool platform: '+key)
cache=root/'.cache';cache.mkdir(exist_ok=True)
for name,asset in lock['platforms'][key].items():
 target=cache/asset['url'].rsplit('/',1)[1]
 if not target.exists():urllib.request.urlretrieve(asset['url'],target)
 if hashlib.sha256(target.read_bytes()).hexdigest()!=asset['sha256']:raise SystemExit('Checksum mismatch: '+name)
 with tarfile.open(target) as archive:archive.extractall(cache,filter='data')
 print(name+': verified and extracted to '+str(cache))
