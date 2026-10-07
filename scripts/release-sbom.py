#!/usr/bin/env python3
"""Inventory exact OCI bytes; source/license completeness is a separate release gate."""
import argparse
import base64
import hashlib
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def props(**values):
    return [{'name': 'mikrocentauri:' + k, 'value': str(v)} for k, v in sorted(values.items())]


def blob(layout, descriptor):
    digest = descriptor['digest']
    if not digest.startswith('sha256:') or len(digest) != 71 or any(c not in '0123456789abcdef' for c in digest[7:]):
        raise ValueError('unsupported OCI digest')
    data = (layout / 'blobs/sha256' / digest[7:]).read_bytes()
    if sha(data) != digest[7:] or len(data) != descriptor['size']:
        raise ValueError('OCI descriptor integrity mismatch')
    return data


def apk_records(text):
    records = []
    seen = set()
    for stanza in text.strip().split('\n\n'):
        item, files, directory = {}, [], ''
        for line in stanza.splitlines():
            if len(line) < 2 or line[1] != ':':
                continue
            key, value = line[0], line[2:]
            if key == 'F':
                directory = value
            elif key == 'R':
                files.append(str(PurePosixPath(directory) / value))
            elif key in 'PVAULocCD':
                if key in item:
                    raise ValueError('duplicate APK metadata field')
                item[key] = value
        if not item or 'P' not in item or 'V' not in item or 'A' not in item:
            raise ValueError('incomplete APK record')
        identity = (item['P'], item['A'])
        if identity in seen:
            raise ValueError('duplicate installed APK')
        seen.add(identity)
        item['files'] = files
        records.append(item)
    return records


def build_info(text):
    info = {'modules': [], 'settings': {}}
    previous = None
    for line in text.splitlines():
        fields = line.strip().split('\t')
        if len(fields) == 1 and ': go' in fields[0]:
            info['go'] = fields[0].rsplit(': ', 1)[1]
        elif fields[0] in ('mod', 'dep') and len(fields) >= 3:
            previous = {'path': fields[1], 'version': fields[2], 'kind': fields[0]}
            if len(fields) > 3:
                previous['sum'] = fields[3]
            info['modules'].append(previous)
        elif fields[0] == '=>':
            if previous is None or len(fields) < 3:
                raise ValueError('invalid Go replacement')
            previous['replacement'] = {'path': fields[1], 'version': fields[2]}
            if len(fields) > 3:
                previous['replacement']['sum'] = fields[3]
        elif fields[0] == 'build' and len(fields) == 2 and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            info['settings'][key] = value
    if 'go' not in info or not info['modules']:
        raise ValueError('missing Go binary build information')
    return info


def component(kind, ref, name, version=None, **extra):
    result = {'type': kind, 'bom-ref': ref, 'name': name, **extra}
    if version:
        result['version'] = version
    return result


def inventory(image_dir, go, frontend_lock):
    layout = image_dir / 'oci'
    index_data = (layout / 'index.json').read_bytes()
    index = json.loads(index_data)
    if len(index.get('manifests', [])) != 2:
        raise ValueError('release must contain exactly two platform manifests')
    root_ref = 'oci:sha256:' + sha(index_data)
    components, dependencies, image_refs = [], [], []
    lock = json.loads(frontend_lock.read_text())
    ui_refs = []
    for path, entry in sorted(lock['packages'].items()):
        if not path:
            continue
        name = path.rsplit('node_modules/', 1)[-1]
        ref = 'npm:' + path + '@' + entry['version']
        runtime = name in ('svelte', 'vite') and path == 'node_modules/' + name
        c = component('library', ref, name, entry['version'], scope='required' if runtime else 'excluded',
                      purl='pkg:npm/' + quote(name, safe='/') + '@' + quote(entry['version'], safe=''),
                      properties=props(evidence='source frontend/package-lock.json; runtime classification from THIRD_PARTY_NOTICES.md',
                                       shipped_role='embedded browser runtime/helper' if runtime else 'build tooling; not asserted shipped'))
        if entry.get('license'):
            c['licenses'] = [{'expression': entry['license']}]
        if entry.get('resolved'):
            reference = {'type': 'distribution', 'url': entry['resolved']}
            if entry.get('integrity', '').startswith('sha512-'):
                reference['hashes'] = [{'alg': 'SHA-512', 'content': base64.b64decode(entry['integrity'][7:], validate=True).hex()}]
            c['externalReferences'] = [reference]
        components.append(c)
        if runtime:
            ui_refs.append(ref)
    for descriptor in sorted(index['manifests'], key=lambda d: d['platform']['architecture']):
        arch = descriptor['platform']['architecture']
        manifest = json.loads(blob(layout, descriptor))
        config = json.loads(blob(layout, manifest['config']))
        if config['architecture'] != arch or config['os'] != 'linux' or len(manifest['layers']) != 1:
            raise ValueError('unsupported image platform or layered layout')
        image_ref = 'image:' + descriptor['digest']
        image_refs.append(image_ref)
        components.append(component('container', image_ref, 'mikrocentauri-' + arch,
                                    hashes=[{'alg': 'SHA-256', 'content': descriptor['digest'][7:]}],
                                    properties=props(architecture=arch, config_digest=manifest['config']['digest'])))
        layer = blob(layout, manifest['layers'][0])
        with tarfile.open(fileobj=io.BytesIO(layer), mode='r:gz') as archive:
            members = {}
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or member.name in members:
                    raise ValueError('unsafe or duplicate OCI layer path')
                members[member.name] = member
            layer_raw = gzip.decompress(layer)
            if config['rootfs']['diff_ids'] != ['sha256:' + sha(layer_raw)]:
                raise ValueError('OCI uncompressed layer integrity mismatch')
            def read(name):
                if name not in members or not members[name].isfile():
                    raise ValueError('required regular image file missing: ' + name)
                return archive.extractfile(members[name]).read()
            installed = read('lib/apk/db/installed')
            refs = []
            for package in apk_records(installed.decode()):
                ref = 'apk:' + arch + ':' + package['P'] + '@' + package['V']
                files = {name: sha(read(name)) for name in package['files'] if name in members and members[name].isfile()}
                evidence = {'architecture': package['A'], 'apk_database_sha256': sha(installed),
                            'apk_package_checksum': package.get('C', ''), 'aports_commit': package.get('c', ''),
                            'origin': package.get('o', ''), 'installed_regular_file_count': len(files),
                            'installed_file_inventory_sha256': sha(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())}
                c = component('library', ref, package['P'], package['V'],
                              purl='pkg:apk/alpine/' + package['P'] + '@' + package['V'] + '?arch=' + package['A'],
                              properties=props(**evidence))
                if package.get('L'):
                    c['licenses'] = [{'expression': package['L']}]
                if package.get('U'):
                    c['externalReferences'] = [{'type': 'website', 'url': package['U']}]
                if package.get('c') and package.get('o'):
                    c.setdefault('externalReferences', []).append({'type': 'build-meta', 'url': 'https://gitlab.alpinelinux.org/alpine/aports/-/tree/' + package['c'] + '/main/' + package['o']})
                components.append(c)
                refs.append(ref)
            for executable in ('mikrocentauri', 'sing-box'):
                binary = read('usr/bin/' + executable)
                if executable == 'mikrocentauri':
                    for package, suffix in [('svelte', ' runtime'), ('vite', ' generated module-preload helper')]:
                        version = lock['packages']['node_modules/' + package]['version']
                        marker = (package.capitalize() + ' ' + version + suffix).encode()
                        if marker not in binary:
                            raise ValueError('embedded UI notice does not match source lock: ' + package)
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / executable
                    path.write_bytes(binary)
                    info = build_info(subprocess.check_output([str(go), 'version', '-m', str(path)], text=True))
                if info['settings'].get('GOARCH') != arch or info['settings'].get('GOOS') != 'linux':
                    raise ValueError('Go binary platform mismatch')
                ref = 'binary:' + arch + ':' + executable
                c = component('application', ref, executable, hashes=[{'alg': 'SHA-256', 'content': sha(binary)}],
                              licenses=[{'expression': 'MIT' if executable == 'mikrocentauri' else 'GPL-3.0-or-later'}],
                              properties=props(path='/usr/bin/' + executable, architecture=arch, go_build_information=json.dumps(info, sort_keys=True, separators=(',', ':'))))
                components.append(c)
                refs.append(ref)
                go_ref = 'stdlib:' + arch + ':' + executable + ':' + info['go']
                components.append(component('library', go_ref, 'Go standard library', info['go'],
                                            licenses=[{'expression': 'BSD-3-Clause'}], properties=props(evidence='binary Go build information; library subsets not enumerated')))
                module_refs = [go_ref] + (ui_refs if executable == 'mikrocentauri' else [])
                for number, module in enumerate(info['modules']):
                    if module['kind'] == 'mod':
                        c['version'] = module['version']
                        continue
                    resolved = module.get('replacement', module)
                    module_ref = ref + ':module:' + str(number)
                    components.append(component('library', module_ref, resolved['path'], resolved['version'],
                                                purl='pkg:golang/' + quote(resolved['path'], safe='/') + '@' + quote(resolved['version'], safe=''),
                                                properties=props(go_module_checksum=resolved.get('sum', ''),
                                                                 license_status='not assessed; module inventory does not imply source/license completeness',
                                                                 original_module=json.dumps(module, sort_keys=True))))
                    module_refs.append(module_ref)
                dependencies.append({'ref': ref, 'dependsOn': sorted(module_refs)})
            dependencies.append({'ref': image_ref, 'dependsOn': sorted(refs)})
    if len(set(image_refs)) != 2 or {d['platform']['architecture'] for d in index['manifests']} != {'amd64', 'arm64'}:
        raise ValueError('release must contain exactly amd64 and arm64')
    dependencies.append({'ref': root_ref, 'dependsOn': sorted(image_refs)})
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': component('container', root_ref, 'MikroCentauri OCI release', hashes=[{'alg': 'SHA-256', 'content': sha(index_data)}]),
                         'properties': props(inventory_scope='Exact OCI installed APK files and Go build metadata; frontend lockfile build dependencies excluded except documented embedded Svelte runtime and Vite helper',
                                             frontend_lock_sha256=sha(frontend_lock.read_bytes()),
                                             source_license_gate='SBOM is an inventory, not a complete corresponding-source or license clearance declaration')},
            'components': sorted(components, key=lambda c: c['bom-ref']),
            'dependencies': sorted(dependencies, key=lambda d: d['ref'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--go', type=Path, default=ROOT / '.cache/go/bin/go')
    parser.add_argument('--frontend-lock', type=Path, default=ROOT / 'frontend/package-lock.json')
    args = parser.parse_args()
    document = inventory(args.image_dir.resolve(), args.go.resolve(), args.frontend_lock.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    print('SBOM:', len(document['components']), 'components;', sha(args.output.read_bytes()))


if __name__ == '__main__':
    main()
