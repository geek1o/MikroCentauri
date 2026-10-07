#!/usr/bin/env python3
"""Regression checks for immutable image publication without registry writes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-ghcr.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
public_spec = importlib.util.spec_from_file_location('public_pull', Path(__file__).with_name('ci-check-public-image.py'))
public_pull = importlib.util.module_from_spec(public_spec)
public_spec.loader.exec_module(public_pull)


class Response:
    def __init__(self, data=b'', headers=None):
        self.data = data
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return self.data


class Publication(unittest.TestCase):
    def test_private_sources_block_catalog_before_registry_probe(self):
        source = 'https://github.com/owner/app/releases/download/build-test/corresponding-sources.tar.gz'
        with patch.object(public_pull, 'urlopen', side_effect=HTTPError(source,404,'Not Found',{},None)) as opener:
            with self.assertRaisesRegex(SystemExit,'sources are not publicly downloadable'):
                public_pull.verify('ghcr.io/owner/app@sha256:'+'a'*64,source)
            self.assertEqual(opener.call_count,1)
            self.assertEqual(opener.call_args.args[0].method,'HEAD')
            self.assertNotIn('Authorization',opener.call_args.args[0].headers)

    def test_local_descriptor_requires_exact_hash_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'image bytes'
            digest = 'sha256:' + hashlib.sha256(data).hexdigest()
            path = root / 'blobs/sha256' / digest[7:]
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            self.assertEqual(publisher.checked_blob(root, {'digest': digest, 'size': len(data)}), data)
            with self.assertRaises(ValueError):
                publisher.checked_blob(root, {'digest': digest, 'size': len(data) + 1})
            path.write_bytes(b'changed bytes')
            with self.assertRaises(ValueError):
                publisher.checked_blob(root, {'digest': digest, 'size': len(data)})

    def test_upload_is_verified_by_immutable_refetch(self):
        registry = object.__new__(publisher.Registry)
        data = json.dumps({'schemaVersion': 2}).encode()
        digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        with patch.object(registry, 'request', side_effect=[Response(headers={'Docker-Content-Digest': digest}), Response(data)]) as requests:
            self.assertEqual(registry.manifest('sha-test', data, 'application/vnd.oci.image.index.v1+json'), digest)
            self.assertEqual(requests.call_args_list[1].args, ('manifests/' + digest,))
        with patch.object(registry, 'request', side_effect=[Response(headers={'Docker-Content-Digest': digest}), Response(b'changed')]):
            with self.assertRaises(ValueError):
                registry.manifest('sha-test', data, 'application/vnd.oci.image.index.v1+json')

    def test_token_never_sent_to_foreign_upload_origin(self):
        registry = object.__new__(publisher.Registry)
        registry.base = 'https://ghcr.io/v2/owner/app/'
        registry.token = 'private-test-token'
        with patch.object(publisher, 'urlopen') as opener:
            with self.assertRaises(ValueError):
                registry.request('https://foreign.example/upload', method='PUT', data=b'x')
            opener.assert_not_called()

    def test_redirect_does_not_forward_registry_credentials(self):
        request = publisher.Request('https://ghcr.io/v2/owner/app/blobs/digest', headers={'Authorization': 'Bearer private-test-token'})
        redirected = publisher.SafeRedirect().redirect_request(request, None, 302, 'Found', {}, 'https://pkg-containers.githubusercontent.com/blob')
        self.assertFalse(redirected.has_header('Authorization'))
        with self.assertRaises(ValueError):
            publisher.SafeRedirect().redirect_request(request, None, 302, 'Found', {}, 'http://ghcr.io/plaintext')


if __name__ == '__main__':
    unittest.main()
