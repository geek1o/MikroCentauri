#!/usr/bin/env python3
"""Archive safety and deterministic image-layer regressions, no Docker required."""
import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('app_image', ROOT / 'scripts/build-app-image.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
render_spec = importlib.util.spec_from_file_location('render_app', ROOT / 'scripts/render-app.py')
renderer = importlib.util.module_from_spec(render_spec)
render_spec.loader.exec_module(renderer)


def base(name='etc/example', content=b'base', timestamp=123):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as archive:
        member = tarfile.TarInfo(name)
        member.mtime, member.size = timestamp, len(content)
        archive.addfile(member, io.BytesIO(content))
    return result.getvalue()


class ImageSafety(unittest.TestCase):
    def test_reproducible_layer_discards_upstream_time(self):
        additions = {'usr/bin/mikrocentauri': (b'controller', 0o755)}
        a = builder.make_layer(base(timestamp=12), additions)
        b = builder.make_layer(base(timestamp=99999999), additions)
        self.assertEqual(a, b)
        with tarfile.open(fileobj=io.BytesIO(a)) as archive:
            self.assertEqual(archive.getmember('data').mode, 0o700)
            self.assertEqual(archive.getmember('usr/bin/mikrocentauri').mode, 0o755)

    def test_traversal_and_overrides_rejected(self):
        for name in ['../../etc/passwd', '/absolute']:
            with self.assertRaises(ValueError):
                builder.make_layer(base(name), {})
        with self.assertRaises(ValueError):
            builder.make_layer(base(), {'etc/example': (b'override', 0o600)})

    def test_elf_wrong_architecture_rejected(self):
        fake = bytearray(64)
        fake[:6] = b'\x7fELF\x02\x01'
        fake[18:20] = (62).to_bytes(2, 'little')
        builder.elf(fake, 'amd64')
        with self.assertRaises(ValueError):
            builder.elf(fake, 'arm64')

    def test_manifest_requires_actual_built_digest(self):
        evidence = {'index_digest': 'sha256:' + 'a' * 64, 'platforms': {'amd64': {}, 'arm64': {}}}
        image = 'registry.invalid/example@' + evidence['index_digest']
        app, catalog = renderer.render(image, evidence)
        self.assertIn(image, app)
        self.assertNotIn('REQUIRED_ACTUAL_IMAGE', app)
        self.assertIn('state:/data', app)
        self.assertEqual(catalog, '-\n' + ''.join('  ' + line + '\n' for line in app.splitlines()))
        for bad in ['registry.invalid/example:latest', image + '\nmalicious: true', 'registry.invalid/example@sha256:' + 'b' * 64]:
            with self.assertRaises(ValueError):
                renderer.render(bad, evidence)

    def test_catalog_draft_stays_in_sync(self):
        app = (ROOT / 'packaging/routeros-app/app.yml').read_text()
        expected = '-\n' + ''.join('  ' + line + '\n' for line in app.splitlines())
        self.assertEqual((ROOT / 'packaging/routeros-app/catalog.yml').read_text(), expected)


if __name__ == '__main__':
    unittest.main()
