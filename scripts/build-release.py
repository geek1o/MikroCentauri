#!/usr/bin/env python3
"""Assemble and verify a local RC from the exact accepted OCI graph.

This does not publish binaries or assert complete corresponding-source coverage.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r'v[0-9]+\.[0-9]+\.[0-9]+-rc\.[1-9][0-9]*')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def archive_tree(directory, output):
    """Stable OCI archive, without host metadata or symlinks."""
    with output.open('wb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w') as archive:
                for path in sorted(directory.rglob('*')):
                    if path.is_symlink() or not path.is_file() and not path.is_dir():
                        raise ValueError('unsupported OCI archive entry')
                    info = tarfile.TarInfo('oci/' + path.relative_to(directory).as_posix())
                    info.mode = 0o755 if path.is_dir() else 0o644
                    info.type = tarfile.DIRTYPE if path.is_dir() else tarfile.REGTYPE
                    info.size = 0 if path.is_dir() else path.stat().st_size
                    if path.is_file():
                        with path.open('rb') as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)


def copy_oci_graph(source, target):
    """Copy only blobs reachable from this index, excluding stale cache images."""
    target.mkdir(parents=True)
    (target / 'blobs/sha256').mkdir(parents=True)
    for name in ['index.json', 'oci-layout']:
        shutil.copyfile(source / name, target / name)
    seen = set()

    def copy(descriptor):
        value = descriptor['digest']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
            raise ValueError('unsafe OCI descriptor')
        path = source / 'blobs/sha256' / value[7:]
        if path.is_symlink() or path.stat().st_size != descriptor['size'] or digest(path) != value[7:]:
            raise ValueError('OCI graph integrity mismatch')
        if value not in seen:
            shutil.copyfile(path, target / 'blobs/sha256' / value[7:])
            seen.add(value)
        return path

    index = json.loads((source / 'index.json').read_text())
    for descriptor in index['manifests']:
        manifest = json.loads(copy(descriptor).read_text())
        copy(manifest['config'])
        for layer in manifest['layers']:
            copy(layer)


def checksum_files(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlinks denied in release')
        if path.is_file() and path != directory / 'SHA256SUMS':
            name = path.relative_to(directory).as_posix()
            if '\n' in name or '\r' in name or '\\' in name:
                raise ValueError('unsafe checksum filename')
            result[name] = digest(path)
    return result


def checksums(directory):
    (directory / 'SHA256SUMS').write_text(''.join(
        value + '  ' + name + '\n' for name, value in checksum_files(directory).items()))


def verify_checksums(directory):
    expected = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('invalid checksum record')
        value, name = match.groups()
        if Path(name).is_absolute() or '..' in Path(name).parts or name in expected:
            raise ValueError('unsafe or duplicate checksum record')
        expected[name] = value
    if expected != checksum_files(directory):
        raise ValueError('release checksum mismatch or missing/extra file')


def verify(directory, distribution=False):
    verify_checksums(directory)
    release = json.loads((directory / 'release.json').read_text())
    if not VERSION.fullmatch(release['version']):
        raise ValueError('invalid release version')
    spec = importlib.util.spec_from_file_location('image_verifier', ROOT / 'scripts/verify-app-image.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify(directory / 'images')
    layout = directory / 'images/oci'
    index = json.loads((layout / 'index.json').read_text())
    reachable = set()
    for descriptor in index['manifests']:
        reachable.add(descriptor['digest'][7:])
        manifest = json.loads((layout / 'blobs/sha256' / descriptor['digest'][7:]).read_text())
        reachable.add(manifest['config']['digest'][7:])
        reachable.update(layer['digest'][7:] for layer in manifest['layers'])
    if reachable != {p.name for p in (layout / 'blobs/sha256').iterdir()}:
        raise ValueError('unreferenced OCI payload denied')
    build = json.loads((directory / 'images/build.json').read_text())
    native = json.loads((directory / 'evidence/native-results.json').read_text())
    if not native['accepted'] or not native['completed'] or not native['hardening']['completed']:
        raise ValueError('native acceptance incomplete')
    if build['index_digest'] != release['image_index_digest']:
        raise ValueError('release image index mismatch')
    with tarfile.open(directory / ('mikrocentauri-' + release['version'] + '-oci.tar.gz'), 'r:gz') as archive:
        expected = {'oci/' + p.relative_to(directory / 'images/oci').as_posix(): p
                    for p in (directory / 'images/oci').rglob('*') if p.is_file()}
        members = [m for m in archive.getmembers() if not m.isdir()]
        if len(members) != len(expected) or {m.name for m in members} != set(expected):
            raise ValueError('OCI archive member mismatch')
        for member in members:
            if not member.isfile() or hashlib.sha256(archive.extractfile(member).read()).hexdigest() != digest(expected[member.name]):
                raise ValueError('OCI archive payload mismatch')
    if native['image_manifest'] != build['platforms']['amd64']['manifest_digest']:
        raise ValueError('accepted amd64 image mismatch')
    if release['runtime_qualified_architectures'] != ['amd64']:
        raise ValueError('unqualified runtime architecture claim')
    for arch, platform in build['platforms'].items():
        if release['controller_source_proof'][arch] != platform['controller_sha256']:
            raise ValueError('controller source proof mismatch')
    bom = json.loads((directory / 'sbom.cdx.json').read_text())
    if bom.get('bomFormat') != 'CycloneDX' or not bom.get('components'):
        raise ValueError('missing component SBOM')
    sbom_digests = {h['content'] for c in bom['components'] for h in c.get('hashes', [])}
    for platform in build['platforms'].values():
        for key in ['controller_sha256', 'engine_sha256']:
            if platform[key] not in sbom_digests:
                raise ValueError('SBOM does not identify shipped binary')
    if distribution:
        # This assembler has no complete corresponding-source validation path.
        # Editing a manifest flag must not turn inventory into compliance proof.
        raise ValueError('binary distribution blocked: complete source/license closure has no verified evidence in this local RC')
    print('RC integrity, accepted image binding and component inventory verified')


def build(args):
    if not VERSION.fullmatch(args.version):
        raise ValueError('RC version must be vMAJOR.MINOR.PATCH-rc.NUMBER')
    output = args.output.resolve()
    if output.exists():
        raise ValueError('output already exists; use a new directory')
    if git('diff', '--name-only', 'HEAD'):
        raise ValueError('commit tracked source changes before building a source-bound RC')
    image = args.image_dir.resolve()
    subprocess.run(['python3', str(ROOT / 'scripts/verify-app-image.py'), '--out', str(image)], check=True)
    evidence_dir = ROOT / 'docs/reports/evidence/phase-7-completion'
    evidence = json.loads((evidence_dir / 'sha256.json').read_text())
    for name, value in evidence.items():
        if digest(evidence_dir / name) != value:
            raise ValueError('Phase 7 evidence hash mismatch: ' + name)
    output.mkdir(parents=True)
    try:
        images = output / 'images'
        images.mkdir()
        copy_oci_graph(image / 'oci', images / 'oci')
        shutil.copy2(image / 'build.json', images / 'build.json')
        image_build = json.loads((image / 'build.json').read_text())
        proof = {}
        for arch in ['amd64', 'arm64']:
            binary = output / ('proof-' + arch)
            subprocess.run([str(args.go.resolve()), 'build', '-buildvcs=false', '-trimpath',
                            '-ldflags=-s -w', '-o', str(binary), './cmd/mikrocentauri'],
                           cwd=ROOT, env=dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0'), check=True)
            proof[arch] = digest(binary)
            binary.unlink()
            if proof[arch] != image_build['platforms'][arch]['controller_sha256']:
                raise ValueError('current source does not reproduce accepted controller: ' + arch)
            shutil.copy2(image / ('mikrocentauri-' + arch + '.tar'), images)
        archive_tree(images / 'oci', output / ('mikrocentauri-' + args.version + '-oci.tar.gz'))
        with (output / ('mikrocentauri-' + args.version + '-source.tar.gz')).open('wb') as source:
            subprocess.run(['git', 'archive', '--format=tar.gz', '--prefix=mikrocentauri/', 'HEAD'],
                           cwd=ROOT, stdout=source, check=True)
        shutil.copytree(evidence_dir, output / 'evidence')
        # Preserve local documentation links; exclude every untracked file.
        for name in git('ls-files', 'docs').splitlines():
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        licenses = output / 'licenses'
        licenses.mkdir()
        for name in ['LICENSE', 'THIRD_PARTY_NOTICES.md']:
            shutil.copy2(ROOT / name, licenses)
        shutil.copy2(ROOT / 'frontend/public/licenses.txt', licenses / 'browser-licenses.txt')
        # This is the exact engine license already shipped in the accepted layer.
        index = json.loads((images / 'oci/index.json').read_text())
        manifest = json.loads((images / 'oci/blobs/sha256' / index['manifests'][0]['digest'].split(':')[1]).read_text())
        layer = images / 'oci/blobs/sha256' / manifest['layers'][0]['digest'].split(':')[1]
        with tarfile.open(layer, 'r:gz') as archive:
            (licenses / 'sing-box-LICENSE').write_bytes(archive.extractfile('usr/share/mikrocentauri/sing-box-LICENSE').read())
        subprocess.run(['python3', str(ROOT / 'scripts/release-sbom.py'), '--image-dir', str(image),
                        '--output', str(output / 'sbom.cdx.json'), '--go', str(args.go.resolve())], check=True)
        write_json(output / 'release.json', {
            'schema': 1, 'version': args.version, 'status': 'local-release-candidate',
            'source_commit': git('rev-parse', 'HEAD'), 'source_tree': git('rev-parse', 'HEAD^{tree}'),
            'image_index_digest': image_build['index_digest'], 'controller_source_proof': proof,
            'runtime_qualified_architectures': ['amd64'],
            'runtime_profile': 'CHR 7.24.5 x86_64 / sing-box 1.14.2; synthetic Phase 7 profile',
            'registry_published': False, 'catalog_published': False,
            'distribution': {'ready': False, 'blockers': [
                'Complete corresponding source and build closure for sing-box native dependencies and Alpine GPL packages has not been assembled',
                'Transitive component license assessment remains incomplete; see SBOM and source-distribution audit']},
            'scope': 'Exact accepted images; local artifact verification adds no native/hardware/browser acceptance',
        })
        checksums(output)
        verify(output)
    except BaseException:
        # Preserve partial output for diagnosis, never treat it as a valid release.
        raise
    print(str(output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='v0.1.0-rc.1')
    parser.add_argument('--image-dir', type=Path, default=ROOT / '.cache/app-image-phase7-complete')
    parser.add_argument('--output', type=Path, default=ROOT / '.cache/releases/v0.1.0-rc.1')
    parser.add_argument('--go', type=Path, default=ROOT / '.cache/go/bin/go')
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--distribution', action='store_true')
    args = parser.parse_args()
    if args.verify:
        verify(args.verify.resolve(), args.distribution)
    else:
        if args.distribution:
            parser.error('--distribution requires --verify')
        build(args)
