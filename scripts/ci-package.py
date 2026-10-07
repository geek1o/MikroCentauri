#!/usr/bin/env python3
"""Package a CI build, its verified corresponding sources and exact inventory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive(directory, output):
    with output.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for path in sorted(directory.rglob('*')):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise ValueError('unsupported package entry: ' + str(path))
                info = tar.gettarinfo(str(path), arcname=path.relative_to(directory).as_posix())
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                if path.is_file():
                    with path.open('rb') as source:
                        tar.addfile(info, source)
                else:
                    tar.addfile(info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-dir', type=Path, default=ROOT / '.cache/app-image')
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/package')
    args = parser.parse_args()
    image, out = args.image_dir.resolve(), args.out.resolve()
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True).strip():
        raise ValueError('commit source changes before producing a source-bound distribution')
    subprocess.run(['python3', str(ROOT / 'scripts/verify-app-image.py'), '--out', str(image)], check=True)
    subprocess.run(['python3', str(ROOT / 'scripts/verify-distribution-sources.py'), '--image-dir', str(image)], check=True)
    if out.exists():
        raise ValueError('package output already exists')
    out.mkdir(parents=True)
    archive(image / 'oci', out / 'mikrocentauri-oci.tar.gz')
    archive(image / 'sources', out / 'corresponding-sources.tar.gz')
    for name in ['build.json', 'sbom.cdx.json', 'mikrocentauri-amd64.tar', 'mikrocentauri-arm64.tar']:
        shutil.copyfile(image / name, out / name)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    with (out / 'mikrocentauri-source.tar.gz').open('wb') as stream:
        subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=mikrocentauri/', commit], cwd=ROOT, stdout=stream, check=True)
    for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
        shutil.copyfile(ROOT / name, out / name)
    (out / 'provenance.json').write_text(json.dumps({
        'source_commit': commit,
        'image_index_digest': json.loads((image / 'build.json').read_text())['index_digest'],
        'qualification': 'CI build and smoke verification; native RouterOS acceptance must be established for these exact bytes',
    }, indent=2) + '\n')
    (out / 'SHA256SUMS').write_text(''.join(sha(path) + '  ' + path.name + '\n' for path in sorted(out.iterdir()) if path.is_file()))
    print('Verified package:', out)


if __name__ == '__main__':
    main()
