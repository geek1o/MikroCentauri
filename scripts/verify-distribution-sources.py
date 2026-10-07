#!/usr/bin/env python3
"""Verify source hashes, installed APK coverage and offline engine reproduction."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / ('scripts/' + name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify(image, go):
    builder = load('build-distributable-image')
    inventory_helper = load('release-sbom')
    alpine_helper = load('collect-alpine-sources')
    sources = image / 'sources'
    inventory = json.loads((sources / 'source-inventory.json').read_text())
    files = {p.relative_to(sources).as_posix(): builder.digest(p) for p in sources.rglob('*') if p.is_file() and p.name != 'source-inventory.json'}
    if any(p.is_symlink() for p in sources.rglob('*')) or files != inventory['files']:
        raise ValueError('corresponding-source file set or checksum mismatch')
    build = json.loads((image / 'build.json').read_text())
    layout = image / 'oci'
    index_bytes = (layout / 'index.json').read_bytes()
    image_digest = 'sha256:' + hashlib.sha256(index_bytes).hexdigest()
    if inventory['image_index_digest'] != image_digest or build['index_digest'] != image_digest:
        raise ValueError('source closure bound to a different image')
    recipe = json.loads((sources / 'engine-build.json').read_text())
    if (recipe['source_commit'], recipe['tags'], recipe['ldflags']) != (builder.COMMIT, builder.TAGS, builder.FLAGS):
        raise ValueError('unsupported engine build recipe')
    if builder.digest(sources / 'sing-box-upstream-source.tar.gz') != builder.SOURCE_SHA:
        raise ValueError('upstream source differs from pinned immutable commit')
    module_archives = json.loads((sources / 'go-module-sources.json').read_text())
    if sorted(item['module'] for item in module_archives) != recipe['vendor_modules']:
        raise ValueError('preferred module source archives do not cover compiled dependency set')
    for item in module_archives:
        if builder.digest(sources / item['file']) != item['sha256']:
            raise ValueError('preferred module source archive hash mismatch')
        with tarfile.open(sources / item['file']) as archive:
            if not any(Path(m.name).name.lower().startswith(('license', 'licence', 'copying')) for m in archive.getmembers() if m.isfile()):
                raise ValueError('preferred module source license missing')
    expected_packages = []
    engines = {}
    index = json.loads(index_bytes)
    if {d['platform']['architecture'] for d in index['manifests']} != {'amd64', 'arm64'} or len(index['manifests']) != 2:
        raise ValueError('exactly two supported image architectures required')
    for descriptor in index['manifests']:
        arch = descriptor['platform']['architecture']
        manifest = json.loads(inventory_helper.blob(layout, descriptor))
        if len(manifest['layers']) != 1:
            raise ValueError('single normalized rootfs layer required')
        layer = inventory_helper.blob(layout, manifest['layers'][0])
        expected_packages.extend(alpine_helper.records(io.BytesIO(layer)))
        with tarfile.open(fileobj=io.BytesIO(layer), mode='r:gz') as archive:
            engines[arch] = hashlib.sha256(archive.extractfile('usr/bin/sing-box').read()).hexdigest()
        if engines[arch] != build['platforms'][arch]['engine_sha256'] or engines[arch] != recipe['platforms'][arch]['binary_sha256']:
            raise ValueError('shipped engine differs from source recipe output')
    alpine = json.loads((sources / 'alpine-sources.json').read_text())
    actual_packages = [p for origin in alpine['origins'] for p in origin['packages']]
    canonical = lambda records: sorted(json.dumps(p, sort_keys=True) for p in records)
    if canonical(actual_packages) != canonical(expected_packages):
        raise ValueError('Alpine source recipes do not cover exact shipped packages')
    for origin in alpine['origins']:
        directory = sources / 'alpine' / origin['origin'] / origin['aports_revision']
        recipe_path = directory / 'APKBUILD'
        if builder.digest(recipe_path) != origin['recipe_sha256']:
            raise ValueError('Alpine recipe hash mismatch')
        expected = alpine_helper.checksums(recipe_path.read_text())
        recorded = {item['file']: item['sha512'] for item in origin['inputs']}
        if expected != recorded:
            raise ValueError('Alpine input set differs from exact recipe checksums')
        for item in origin['inputs']:
            path = directory / item['file']
            if hashlib.sha512(path.read_bytes()).hexdigest() != item['sha512'] or builder.digest(path) != item['sha256']:
                raise ValueError('Alpine corresponding-source input hash mismatch')
    # Hashes alone cannot prove preferred source reproduces a distributed binary.
    with tempfile.TemporaryDirectory(prefix='mikrocentauri-source-check-') as directory:
        source = Path(directory) / 'source'
        source.mkdir()
        with tarfile.open(sources / 'sing-box-linux-source.tar.gz') as archive:
            if any(not member.isfile() for member in archive.getmembers()):
                raise ValueError('source archive must contain regular preferred-source files')
            archive.extractall(source, filter='data')
        if not (source / 'LICENSE').is_file() or not (source / 'vendor/modules.txt').is_file():
            raise ValueError('engine license or vendored dependencies absent')
        compiled_modules = set()
        for arch in ['amd64', 'arm64']:
            output = Path(directory) / ('sing-box-' + arch)
            info = builder.build_engine(go, source, output, arch)
            if builder.digest(output) != engines[arch]:
                raise ValueError('offline source rebuild does not reproduce shipped engine: ' + arch)
            compiled_modules.update(m.get('Replace', m)['Path'] for m in info['Deps'])
        if sorted(compiled_modules) != recipe['vendor_modules']:
            raise ValueError('engine compiled dependency closure mismatch')
        for module in compiled_modules:
            directory = source / 'vendor' / module
            if not any(p.is_file() and p.name.lower().startswith(('license', 'licence', 'copying')) for p in directory.iterdir()):
                raise ValueError('compiled module license missing: ' + module)
    print('Corresponding sources: hashes, exact Alpine recipes and offline two-platform engine reproduction verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-dir', required=True, type=Path)
    parser.add_argument('--go', type=Path, default=ROOT / '.cache/go/bin/go')
    args = parser.parse_args()
    verify(args.image_dir.resolve(), args.go.resolve())
