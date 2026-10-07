#!/usr/bin/env python3
"""Source-closure checksum/parser regression checks; no external network calls."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('alpine_sources', ROOT / 'scripts/collect-alpine-sources.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class SourceChecks(unittest.TestCase):
    def test_metadata_package_needs_no_external_input(self):
        self.assertEqual(collector.checksums('pkgname=alpine-base\npackage() { :; }\n'), {})

    def test_source_without_checksums_is_rejected(self):
        with self.assertRaises(ValueError):
            collector.checksums('source="https://example.invalid/archive.tar.gz"\n')

    def test_unsafe_and_duplicate_names_are_rejected(self):
        checksum = 'a' * 128
        for entries in (f'{checksum} ../source\n', f'{checksum} source\n{checksum} source\n'):
            with self.assertRaises(ValueError):
                collector.checksums('sha512sums="\n' + entries + '"\n')

    def test_unverified_cache_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            cache = directory / 'cache'
            cache.mkdir()
            expected = 'a' * 128
            (cache / expected).write_bytes(b'altered source')
            original = collector.download
            collector.download = lambda _: ('source="source.tar.gz"\nsha512sums="\n' + expected + ' source.tar.gz\n"').encode()
            try:
                with self.assertRaisesRegex(ValueError, 'cached source checksum mismatch'):
                    collector.collect_origin(('pkg', 'b' * 40), [], directory / 'out', cache)
                self.assertFalse((directory / 'out/alpine/pkg' / ('b' * 40) / 'source.tar.gz').exists())
            finally:
                collector.download = original

    def test_remote_recipe_is_not_executed(self):
        recipe = 'pkgver=1.2.3\nsource="archive.tar.gz::https://example.invalid/pkg-$pkgver.tar.gz\n$(touch /tmp/invalid)"\n'
        self.assertEqual(collector.remote_sources(recipe), {'archive.tar.gz': 'https://example.invalid/pkg-1.2.3.tar.gz'})


if __name__ == '__main__':
    unittest.main()
