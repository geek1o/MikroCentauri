#!/usr/bin/env python3
"""Build and copy the self-contained UI into Go's embedded filesystem."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='require checked-in assets to match')
    args = parser.parse_args()
    subprocess.run(['npm', 'ci', '--no-audit', '--no-fund'], cwd=ROOT/'frontend', check=True)
    subprocess.run(['npm', 'run', 'check'], cwd=ROOT/'frontend', check=True)
    subprocess.run(['npm', 'test'], cwd=ROOT/'frontend', check=True)
    subprocess.run(['npm', 'run', 'build'], cwd=ROOT/'frontend', check=True)
    source, target = ROOT/'frontend/dist', ROOT/'internal/webui/dist'
    files = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob('*') if p.is_file()}
    if {'index.html','licenses.txt'} <= set(files) and all(p in {'index.html','licenses.txt'} or p.startswith('assets/') and p.endswith(('.js', '.css', '.svg')) for p in files):
        pass
    else:
        raise SystemExit('unexpected bundle files')
    compressed = sum(len(gzip.compress(data, mtime=0)) for data in files.values())
    if compressed > 100_000:
        raise SystemExit(f'UI exceeds 100000 gzip-byte budget: {compressed}')
    if args.check:
        actual = {str(p.relative_to(target)): p.read_bytes() for p in target.rglob('*') if p.is_file()}
        if actual != files:
            raise SystemExit('embedded UI is stale; run scripts/build-webui.py')
    else:
        if target.exists(): shutil.rmtree(target)
        shutil.copytree(source, target)
    print(json.dumps({'gzip_bytes': compressed, 'files': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())}}, indent=2))

if __name__ == '__main__': main()
