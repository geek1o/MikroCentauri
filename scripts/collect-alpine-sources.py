#!/usr/bin/env python3
"""Collect exact Alpine recipe/source inputs from shipped rootfs APK metadata.

Does not execute downloaded APKBUILD code. Source hashes are checked against the
immutable upstream recipes. Output is material for a source distribution, not a
claim that arbitrary image components have been legally cleared.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import tarfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def download(url):
    with urlopen(Request(url, headers={'User-Agent': 'MikroCentauri-source-collector'}), timeout=90) as response:
        return response.read()


def records(rootfs):
    with tarfile.open(fileobj=rootfs, mode='r:*') if hasattr(rootfs, "read") else tarfile.open(rootfs, 'r:*') as archive:
        candidates = [m for m in archive.getmembers() if m.name.lstrip('./') == 'lib/apk/db/installed']
        if len(candidates) != 1 or not candidates[0].isfile():
            raise ValueError('one regular installed APK database required')
        text = archive.extractfile(candidates[0]).read().decode()
    items = []
    for paragraph in text.split('\n\n'):
        fields = {line[0]: line[2:] for line in paragraph.splitlines()
                  if len(line) > 1 and line[1] == ':' and line[0] in 'PVoLcA'}
        if 'P' not in fields:
            continue
        if not re.fullmatch(r'[a-z0-9+_.-]+', fields.get('o', '')) or not re.fullmatch(r'[0-9a-f]{40}', fields.get('c', '')):
            raise ValueError('package origin and exact aports revision required')
        items.append(fields)
    return items


def checksums(recipe):
    match = re.search(r'^sha512sums="(.*?)"', recipe, re.M | re.S)
    if not match:
        if not re.search(r'^\s*source=', recipe, re.M):
            return {}  # Generated metadata-only packages have no external inputs.
        raise ValueError('exact sha512sums required')
    values = {}
    for line in match.group(1).splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r'[0-9a-f]{128}', fields[0]):
            raise ValueError('unsupported recipe checksum format')
        name = fields[1]
        if Path(name).name != name or name in ('.', '..') or name in values:
            raise ValueError('unsafe/duplicate source filename')
        values[name] = fields[0]
    return values


def remote_sources(recipe):
    # Read only scalar assignments; reject unevaluated shell syntax. APKBUILD is
    # retained verbatim for the recipient but is never sourced on the build host.
    variables = {}
    for key, value in re.findall(r'^([A-Za-z_][A-Za-z0-9_]*)=([^\n]*)$', recipe, re.M):
        value = value.strip().strip('"').strip("'")
        if re.fullmatch(r'[a-zA-Z0-9._+/-]+', value):
            variables[key] = value
    match = re.search(r'^source="(.*?)"', recipe, re.M | re.S)
    if not match:
        return {}
    expanded = match.group(1)
    for _ in range(3):
        expanded = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)',
                          lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), expanded)
    urls = {}
    for token in expanded.split():
        name, url = token.split('::', 1) if '::' in token else (token.rsplit('/', 1)[-1], token)
        if url.startswith('https://') and '$' not in url:
            urls[name] = url
    return urls


def collect_origin(key, packages, output, cache):
    origin, revision = key
    prefix = f'https://raw.githubusercontent.com/alpinelinux/aports/{revision}/main/{origin}/'
    directory = output / 'alpine' / origin / revision
    directory.mkdir(parents=True, exist_ok=True)
    recipe = download(prefix + 'APKBUILD')
    (directory / 'APKBUILD').write_bytes(recipe)
    recipe_text = recipe.decode()
    sums = checksums(recipe_text)
    fallback = remote_sources(recipe_text)
    inputs = []
    for name, expected in sums.items():
        cached = cache / expected
        url_used = None
        if cached.is_file():
            data = cached.read_bytes()
        else:
            choices = [prefix + quote(name),
                       'https://distfiles.alpinelinux.org/distfiles/v3.24/' + quote(name),
                       'https://distfiles.alpinelinux.org/distfiles/edge/' + quote(name)]
            if name in fallback:
                choices.append(fallback[name])
            data = None
            failures = []
            for url in choices:
                try:
                    candidate = download(url)
                    if hashlib.sha512(candidate).hexdigest() != expected:
                        failures.append('hash mismatch: ' + url)
                        continue
                    data, url_used = candidate, url
                    break
                except (HTTPError, OSError) as exc:
                    failures.append(f'{url}: {type(exc).__name__}')
            if data is None:
                raise ValueError(f'cannot obtain verified {origin}/{name}: ' + '; '.join(failures))
            cached.write_bytes(data)
        if hashlib.sha512(data).hexdigest() != expected:
            raise ValueError('cached source checksum mismatch')
        (directory / name).write_bytes(data)
        inputs.append({'file': name, 'sha512': expected, 'sha256': hashlib.sha256(data).hexdigest(),
                       'bytes': len(data), 'download': url_used or 'verified-local-cache'})
    return {'origin': origin, 'aports_revision': revision,
            'packages': sorted(packages, key=lambda p: (p['P'], p['A'])),
            'recipe_sha256': hashlib.sha256(recipe).hexdigest(), 'inputs': inputs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, action='append', default=[])
    parser.add_argument('--image-dir', type=Path)
    parser.add_argument('--output', '--output-dir', dest='output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path('.cache/alpine-corresponding-source'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    roots = list(args.rootfs)
    if args.image_dir:
        import io
        layout = args.image_dir / 'oci'
        index = json.loads((layout / 'index.json').read_bytes())
        def blob(descriptor):
            digest = descriptor['digest']
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
                raise ValueError('invalid OCI descriptor')
            data = (layout / 'blobs/sha256' / digest[7:]).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest[7:] or len(data) != descriptor['size']:
                raise ValueError('OCI blob integrity mismatch')
            return data
        for descriptor in index['manifests']:
            manifest = json.loads(blob(descriptor))
            databases = []
            for layer in manifest['layers']:
                stream = io.BytesIO(blob(layer))
                with tarfile.open(fileobj=stream, mode='r:*') as archive:
                    if any(m.name.lstrip('./') == 'lib/apk/db/installed' for m in archive.getmembers()):
                        stream.seek(0)
                        databases.append(stream)
            if len(databases) != 1:
                raise ValueError('one APK database layer required per platform')
            roots.extend(databases)
    if not roots:
        parser.error('--image-dir or --rootfs required')
    groups = {}
    for rootfs in roots:
        for item in records(rootfs):
            groups.setdefault((item['o'], item['c']), []).append(item)
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(collect_origin, key, packages, args.output, args.cache)
                   for key, packages in sorted(groups.items())]
        origins = [future.result() for future in futures]
    inventory = {'schema': 1, 'alpine_branch': 'v3.24', 'origins': origins,
                 'scope': 'recipe checksum inputs of installed package origins; not independent legal clearance'}
    (args.output / 'alpine-sources.json').write_text(json.dumps(inventory, indent=2, sort_keys=True) + '\n')
    (args.output / 'ALPINE-BUILD.md').write_text(
        '# Alpine source inputs\n\n'
        'Each origin directory contains the exact immutable aports APKBUILD and every\n'
        'SHA512-pinned source/configuration/patch input it lists. The package database\n'
        'identifies the shipped versions and architecture. Use Alpine v3.24 abuild\n'
        'with the recipe dependencies to build the origin; consult each retained\n'
        'APKBUILD for its prepare/build/package and split-package procedures.\n'
        'The application image builder uses the pinned official minirootfs; these\n'
        'inputs support modification/rebuilding, not a promise of reproducible APK bytes.\n')
    print(f'Collected {len(origins)} immutable Alpine package origins')


if __name__ == '__main__':
    main()
