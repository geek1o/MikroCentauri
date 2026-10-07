#!/usr/bin/env python3
"""RC integrity regressions; do not build or execute a new native image."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_builder', ROOT / 'scripts/build-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class Integrity(unittest.TestCase):
    def test_mutated_deleted_and_extra_payload_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = root / 'image.tar'
            item.write_bytes(b'immutable accepted image')
            release.checksums(root)
            release.verify_checksums(root)
            item.write_bytes(b'mutated image')
            with self.assertRaises(ValueError):
                release.verify_checksums(root)
            item.write_bytes(b'immutable accepted image')
            extra = root / 'unlisted-private-file'
            extra.write_bytes(b'not an intended release artifact')
            with self.assertRaises(ValueError):
                release.verify_checksums(root)
            extra.unlink()
            item.unlink()
            with self.assertRaises(ValueError):
                release.verify_checksums(root)

    def test_unsafe_duplicate_and_symlink_payload_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'image').write_bytes(b'image')
            release.checksums(root)
            sums = root / 'SHA256SUMS'
            sums.write_text(sums.read_text() * 2)
            with self.assertRaises(ValueError):
                release.verify_checksums(root)
            sums.write_text('a' * 64 + '  ../outside\n')
            with self.assertRaises(ValueError):
                release.verify_checksums(root)
            (root / 'link').symlink_to(root / 'image')
            with self.assertRaises(ValueError):
                release.checksums(root)

    def test_oci_archive_independent_of_host_mtime(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            layout = root / 'oci'
            layout.mkdir()
            item = layout / 'index.json'
            item.write_bytes(b'index')
            release.archive_tree(layout, root / 'first.gz')
            os.utime(item, (1000000000, 1000000000))
            release.archive_tree(layout, root / 'second.gz')
            self.assertEqual((root / 'first.gz').read_bytes(), (root / 'second.gz').read_bytes())

    def test_version_rejects_path_or_stable_release(self):
        for version in ['../rc', 'v1.0.0', 'v0.1.0-rc.0', 'v0.1.0-rc.1\n']:
            self.assertIsNone(release.VERSION.fullmatch(version))
        self.assertIsNotNone(release.VERSION.fullmatch('v0.1.0-rc.1'))

    def test_cached_orphan_image_excluded_and_corrupt_graph_rejected(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'oci'
            blobs = source / 'blobs/sha256'
            blobs.mkdir(parents=True)

            def blob(data):
                path = blobs / release.hashlib.sha256(data).hexdigest()
                path.write_bytes(data)
                return {'digest': 'sha256:' + path.name, 'size': len(data)}

            config = blob(b'accepted config')
            layer = blob(b'accepted layer')
            orphan = blob(b'unaccepted old image payload')
            manifest = blob(json.dumps({'config': config, 'layers': [layer]}).encode())
            (source / 'index.json').write_text(json.dumps({'manifests': [manifest]}))
            (source / 'oci-layout').write_text('{}')
            release.copy_oci_graph(source, root / 'release-oci')
            actual = {p.name for p in (root / 'release-oci/blobs/sha256').iterdir()}
            self.assertNotIn(orphan['digest'][7:], actual)
            self.assertEqual(len(actual), 3)
            (blobs / layer['digest'][7:]).write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                release.copy_oci_graph(source, root / 'invalid-oci')


if __name__ == '__main__':
    unittest.main()
