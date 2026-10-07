#!/usr/bin/env python3
"""Release inventory regressions: integrity, provenance and shipped/build scopes."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_sbom', ROOT / 'scripts/release-sbom.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    def test_descriptor_tamper_and_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            layout = Path(folder)
            content = b'exact accepted bytes'
            directory = layout / 'blobs/sha256'
            directory.mkdir(parents=True)
            (directory / module.sha(content)).write_bytes(content)
            descriptor = {'digest': 'sha256:' + module.sha(content), 'size': len(content)}
            self.assertEqual(module.blob(layout, descriptor), content)
            (directory / module.sha(content)).write_bytes(b'corruption')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                module.blob(layout, descriptor)
            descriptor['digest'] = 'sha256:../../private/bootstrap'
            with self.assertRaisesRegex(ValueError, 'unsupported'):
                module.blob(layout, descriptor)

    def test_apk_identity_and_origin_preserved_not_guessed(self):
        text = 'P:busybox\nV:1.37.0-r31\nA:aarch64\nL:GPL-2.0-only\no:busybox\nc:abc123\nF:bin\nR:busybox\n'
        records = module.apk_records(text)
        self.assertEqual(records[0]['files'], ['bin/busybox'])
        self.assertEqual(records[0]['o'], 'busybox')
        self.assertEqual(records[0]['c'], 'abc123')
        with self.assertRaisesRegex(ValueError, 'duplicate installed'):
            module.apk_records(text + '\n' + text)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            module.apk_records('P:busybox\nA:aarch64\n')

    def test_go_replacements_cgo_and_native_modules_preserved(self):
        info = module.build_info('/tmp/binary: go1.27.1\n\tmod\tupstream/app\tv1.2.3\th1:main\n'
                                 '\tdep\tupstream/module\tv1.0.0\th1:old\n'
                                 '\t=>\tfork/module\tv1.0.1\th1:new\n'
                                 '\tdep\tnative/prebuilt/linux_arm64\tv0.1.0\th1:native\n'
                                 '\tbuild\tCGO_ENABLED=1\n\tbuild\t-tags=with_cronet\n')
        self.assertEqual(info['modules'][1]['replacement']['sum'], 'h1:new')
        self.assertEqual(info['modules'][2]['path'], 'native/prebuilt/linux_arm64')
        self.assertEqual(info['settings']['CGO_ENABLED'], '1')
        self.assertEqual(info['settings']['-tags'], 'with_cronet')
        with self.assertRaisesRegex(ValueError, 'invalid Go replacement'):
            module.build_info('/tmp/binary: go1.27.1\n\t=>\tbroken\tv1\n')
        with self.assertRaisesRegex(ValueError, 'missing Go'):
            module.build_info('/tmp/binary: ELF executable without build metadata')

    @unittest.skipUnless((ROOT / '.cache/app-image-phase7-complete/oci/index.json').exists(), 'accepted local image not present')
    def test_actual_inventory_deterministic_linked_and_honest(self):
        args = (ROOT / '.cache/app-image-phase7-complete', ROOT / '.cache/go/bin/go', ROOT / 'frontend/package-lock.json')
        first = module.inventory(*args)
        second = module.inventory(*args)
        self.assertEqual(first, second)
        components = {c['bom-ref']: c for c in first['components']}
        self.assertEqual(len(components), len(first['components']))
        refs = set(components) | {first['metadata']['component']['bom-ref']}
        for dependency in first['dependencies']:
            self.assertIn(dependency['ref'], refs)
            self.assertTrue(set(dependency['dependsOn']) <= refs)
        self.assertEqual(first['specVersion'], '1.6')
        with tempfile.TemporaryDirectory() as folder:
            stale = json.loads(args[2].read_text())
            stale['packages']['node_modules/svelte']['version'] = '0.0.0-stale'
            lock_path = Path(folder) / 'package-lock.json'
            lock_path.write_text(json.dumps(stale))
            with self.assertRaisesRegex(ValueError, 'embedded UI notice'):
                module.inventory(args[0], args[1], lock_path)
        for name in ('svelte', 'vite'):
            self.assertEqual(components['npm:node_modules/' + name + '@' + json.loads(args[2].read_text())['packages']['node_modules/' + name]['version']]['scope'], 'required')
        self.assertEqual(next(c for c in components.values() if c['name'] == 'typescript')['scope'], 'excluded')
        modules = [c for c in components.values() if ':module:' in c['bom-ref']]
        self.assertTrue(modules)
        self.assertTrue(all(not c.get('licenses') for c in modules))
        self.assertTrue(all(any(p['name'] == 'mikrocentauri:license_status' and 'not assessed' in p['value'] for p in c['properties']) for c in modules))
        self.assertTrue(any('/cronet-go/lib/' in c['name'] for c in modules))
        images = [c for c in components.values() if c['type'] == 'container']
        self.assertEqual(len(images), 2)
        actual_index = json.loads((args[0] / 'oci/index.json').read_text())
        self.assertEqual({c['hashes'][0]['content'] for c in images}, {d['digest'][7:] for d in actual_index['manifests']})


if __name__ == '__main__':
    unittest.main()
