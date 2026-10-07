#!/usr/bin/env python3
"""Build the pinned pure-Go engine and package its reproducible Linux source closure."""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'af6e64c3b69e6132ebaee0e1a3d24e93903f6709'
SOURCE_SHA = 'bbf37fe816fc18621bd0700b71e69dd2a92e3e499f3311d7dff73319999174cf'
TAGS = 'with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api'
FLAGS = '-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.14.2'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / ('scripts/' + name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def build_engine(go, source, binary, arch):
    subprocess.run([str(go), 'build', '-mod=vendor', '-buildvcs=false', '-trimpath', '-tags=' + TAGS,
                    '-ldflags=' + FLAGS, '-o', str(binary), './cmd/sing-box'], cwd=source,
                   env=dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch, GOTOOLCHAIN='local', GOPROXY='off'), check=True)
    info = json.loads(subprocess.check_output([str(go), 'version', '-m', '-json', str(binary)]))
    if not any(s['Key'] == 'CGO_ENABLED' and s['Value'] == '0' for s in info['Settings']):
        raise ValueError('engine is not a pure-Go build')
    if any('cronet' in m['Path'].lower() for m in info['Deps']):
        raise ValueError('native Cronet dependency is outside this source closure')
    return info


def archive_source(source, destination, compiled_modules):
    """Keep upstream preferred source and Linux compiled-module vendor sources/licenses.

    Unsupported feature modules and Windows-only native blobs are excluded.
    The fixed two-architecture build is subsequently reproduced from this archive.
    """
    with destination.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as archive:
            for path in sorted(source.rglob('*')):
                if not path.is_file():
                    continue
                if path.is_symlink():
                    raise ValueError('source symlinks denied')
                name = path.relative_to(source).as_posix()
                if name.startswith('vendor/') and name != 'vendor/modules.txt':
                    relative = name[len('vendor/'):]
                    if not any(relative.startswith(module + '/') for module in compiled_modules):
                        continue
                    if path.suffix.lower() in {'.a', '.so', '.dll', '.dylib', '.exe'}:
                        continue
                info = archive.gettarinfo(str(path), arcname=name)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                with path.open('rb') as content:
                    archive.addfile(info, content)


def module_sources(go, infos, sources):
    """Retain full preferred module sources, including generators and build scripts.

    Vendoring alone can omit .proto or other generator inputs. Windows-only native
    binaries are excluded from this explicitly Linux-scoped source distribution.
    """
    modules = {}
    for info in infos.values():
        for dependency in info['Deps']:
            dependency = dependency.get('Replace', dependency)
            modules[(dependency['Path'], dependency['Version'])] = dependency
    directory = sources / 'go-modules'
    directory.mkdir(exist_ok=True)
    entries = []
    for path, version in sorted(modules):
        details = json.loads(subprocess.check_output([str(go), 'mod', 'download', '-json', path + '@' + version], cwd=ROOT))
        original = Path(details['Zip'])
        name = hashlib.sha256((path + '@' + version).encode()).hexdigest() + '.tar.gz'
        output = directory / name
        omitted = []
        with zipfile.ZipFile(original) as upstream, output.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w') as archive:
                for member in sorted(upstream.infolist(), key=lambda m: m.filename):
                    if member.is_dir():
                        continue
                    relative = member.filename.split('@' + version + '/', 1)[1]
                    if Path(relative).suffix.lower() in {'.a', '.so', '.dll', '.dylib', '.exe'}:
                        omitted.append(relative)
                        continue
                    data = upstream.read(member)
                    item = tarfile.TarInfo(relative)
                    item.size, item.mode = len(data), 0o644
                    archive.addfile(item, io.BytesIO(data))
        entries.append({'module': path, 'version': version, 'go_sum': details['Sum'],
                        'upstream_module_zip_sha256': digest(original), 'file': 'go-modules/' + name,
                        'sha256': digest(output), 'omitted_uncompiled_native_files': omitted})
    (sources / 'go-module-sources.json').write_text(json.dumps(entries, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/app-image')
    parser.add_argument('--go', type=Path, default=ROOT / '.cache/go/bin/go')
    args = parser.parse_args()
    out, go = args.out.resolve(), args.go.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = out / 'sources'
    sources.mkdir(exist_ok=True)
    toolchain = json.loads((ROOT / 'toolchain.lock.json').read_text())
    if subprocess.check_output([str(go), 'version'], text=True).split()[2] != 'go' + toolchain['go_version']:
        raise ValueError('Go version differs from the pinned toolchain')
    cache = ROOT / '.cache/sing-box-source'
    cache.mkdir(parents=True, exist_ok=True)
    source_tar = ROOT / '.cache/sing-box-source.tar.gz'
    url = 'https://codeload.github.com/SagerNet/sing-box/tar.gz/' + COMMIT
    if not source_tar.exists():
        with urllib.request.urlopen(url, timeout=120) as response:
            source_tar.write_bytes(response.read())
    if digest(source_tar) != SOURCE_SHA:
        raise ValueError('pinned engine source archive changed')
    source = cache / ('sing-box-' + COMMIT)
    if not source.exists():
        with tarfile.open(source_tar) as archive:
            archive.extractall(cache, filter='data')
    # go mod vendor carries upstream module checksums and all applicable notices.
    # It considers every upstream feature tag; the distributable archive is pruned
    # to modules actually compiled for the supported Linux configurations below.
    subprocess.run([str(go), 'mod', 'vendor'], cwd=source, env=dict(os.environ, GOTOOLCHAIN='local'), check=True)
    infos = {}
    modules = set()
    lock = copy.deepcopy(json.loads((ROOT / 'packaging/image-assets.lock.json').read_text()))
    for arch in ['amd64', 'arm64']:
        binary = out / ('sing-box-' + arch)
        infos[arch] = build_engine(go, source, binary, arch)
        modules.update(m.get('Replace', m)['Path'] for m in infos[arch]['Deps'])
        archive_path = out / ('engine-' + arch + '.tar.gz')
        with archive_path.open('wb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w') as archive:
                info = tarfile.TarInfo('sing-box')
                info.mode, info.size = 0o755, binary.stat().st_size
                with binary.open('rb') as content:
                    archive.addfile(info, content)
        lock['platforms'][arch]['sing_box'] = {'url': archive_path.as_uri(), 'sha256': digest(archive_path)}
    for module in modules:
        directory = source / 'vendor' / module
        if not any(p.is_file() and p.name.lower().startswith(('license', 'licence', 'copying')) for p in directory.iterdir()):
            raise ValueError('vendored module license missing: ' + module)
    source_bundle = sources / 'sing-box-linux-source.tar.gz'
    archive_source(source, source_bundle, modules)
    module_sources(go, infos, sources)
    shutil.copyfile(source_tar, sources / 'sing-box-upstream-source.tar.gz')
    shutil.copyfile(go.parent.parent / 'LICENSE', sources / 'Go-LICENSE')
    recipe = {'source_commit': COMMIT, 'upstream_url': url, 'upstream_sha256': SOURCE_SHA,
              'go_version': toolchain['go_version'], 'tags': TAGS, 'ldflags': FLAGS,
              'platforms': {arch: {'binary_sha256': digest(out / ('sing-box-' + arch)), 'build_info': infos[arch]} for arch in infos},
              'vendor_modules': sorted(modules),
              'scope': 'Offline reproducible Linux amd64/arm64 builds only; native platform blobs and unused optional modules excluded'}
    (sources / 'engine-build.json').write_text(json.dumps(recipe, indent=2, sort_keys=True) + '\n')
    shutil.copyfile(ROOT / 'scripts/build-distributable-image.py', sources / 'build-distributable-image.py')
    builder = load('build-app-image')
    dependency_notices = []
    for module in sorted(modules):
        for notice in sorted((source / 'vendor' / module).iterdir()):
            if notice.is_file() and notice.name.lower().startswith(('license', 'licence', 'copying', 'notice', 'copyright')):
                dependency_notices.append(('\n===== ' + module + ' / ' + notice.name + ' =====\n').encode() + notice.read_bytes())
    original_layer = builder.make_layer
    def layer_with_licenses(rootfs, additions):
        additions['usr/share/mikrocentauri/engine-dependency-licenses.txt'] = (b''.join(dependency_notices), 0o644)
        additions['usr/share/mikrocentauri/Go-LICENSE'] = ((go.parent.parent / 'LICENSE').read_bytes(), 0o644)
        return original_layer(rootfs, additions)
    builder.make_layer = layer_with_licenses
    original_encode = builder.encode
    def encode_with_source(value):
        if isinstance(value, dict) and 'rootfs' in value and 'config' in value:
            value['config']['Labels'] = {'org.opencontainers.image.source': 'https://github.com/geek1o/MikroCentauri',
                                       'org.opencontainers.image.description': 'Experimental personal-use selective routing application; no warranty'}
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict) and 'RepoTags' in value[0]:
            arch = value[0]['RepoTags'][0].rsplit('-', 1)[-1]
            value[0]['RepoTags'] = ['mikrocentauri:' + arch]
        return original_encode(value)
    builder.encode = encode_with_source
    layout = out / 'oci'
    (layout / 'blobs/sha256').mkdir(parents=True, exist_ok=True)
    assets = ROOT / '.cache/app-image-assets'
    assets.mkdir(parents=True, exist_ok=True)
    descriptors, platforms = [], {}
    for arch in ['amd64', 'arm64']:
        descriptor, platform = builder.build_platform(arch, lock, assets, out, layout, str(go))
        descriptors.append(descriptor)
        # Local file URIs describe a build cache, not a public source address.
        platform['inputs']['sing_box']['url'] = url
        platform['engine_build'] = 'pure-Go source build; CGO_ENABLED=0'
        platforms[arch] = platform
    index = builder.encode({'schemaVersion': 2, 'mediaType': builder.OCI + 'image.index.v1+json', 'manifests': descriptors})
    (layout / 'index.json').write_bytes(index)
    (layout / 'oci-layout').write_bytes(builder.encode({'imageLayoutVersion': '1.0.0'}))
    build = {'schema': 1, 'go_version': toolchain['go_version'], 'index_digest': 'sha256:' + builder.digest(index),
             'platforms': platforms, 'entrypoint': 'app-run', 'volume': '/data', 'registry_published': False,
             'runtime_acceptance': 'new source-built engine; no native acceptance inferred from earlier images'}
    (out / 'build.json').write_text(json.dumps(build, indent=2) + '\n')
    subprocess.run(['python3', str(ROOT / 'scripts/collect-alpine-sources.py'), '--image-dir', str(out), '--output-dir', str(sources)], check=True)
    (sources / 'source-inventory.json').write_text(json.dumps({
        'schema': 1, 'image_index_digest': build['index_digest'],
        'files': {p.relative_to(sources).as_posix(): digest(p) for p in sorted(sources.rglob('*')) if p.is_file() and p.name != 'source-inventory.json'},
    }, indent=2, sort_keys=True) + '\n')
    subprocess.run(['python3', str(ROOT / 'scripts/release-sbom.py'), '--image-dir', str(out), '--output', str(out / 'sbom.cdx.json'), '--go', str(go)], check=True)
    subprocess.run(['python3', str(ROOT / 'scripts/verify-distribution-sources.py'), '--image-dir', str(out), '--go', str(go)], check=True)
    print('Source-complete build:', build['index_digest'])


if __name__ == '__main__':
    main()
