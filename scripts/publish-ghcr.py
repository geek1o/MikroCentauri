#!/usr/bin/env python3
"""Push an exact OCI graph to GHCR and verify the uploaded immutable digest.

GITHUB_TOKEN is read only from the environment and never written to disk.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        if urlsplit(newurl).scheme != 'https':
            raise ValueError('HTTPS registry redirects required')
        if urlsplit(request.full_url).netloc != urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected


urlopen = build_opener(SafeRedirect()).open


class Registry:
    def __init__(self, repository):
        self.repository = repository
        self.base = 'https://ghcr.io/v2/' + repository + '/'
        credentials = (os.environ['GITHUB_ACTOR'] + ':' + os.environ['GITHUB_TOKEN']).encode()
        query = urlencode({'service': 'ghcr.io', 'scope': 'repository:' + repository + ':pull,push'})
        request = Request('https://ghcr.io/token?' + query, headers={'Authorization': 'Basic ' + base64.b64encode(credentials).decode()})
        with urlopen(request, timeout=60) as response:
            self.token = json.load(response)['token']

    def request(self, path, method='GET', data=None, content_type=None):
        url = urljoin(self.base, path)
        if urlsplit(url).scheme != 'https' or urlsplit(url).netloc != 'ghcr.io':
            raise ValueError('unexpected registry upload origin')
        headers = {'Authorization': 'Bearer ' + self.token,
                   'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/octet-stream'}
        if content_type:
            headers['Content-Type'] = content_type
        return urlopen(Request(url, data=data, method=method, headers=headers), timeout=300)

    def blob(self, digest, data):
        try:
            with self.request('blobs/' + digest, method='HEAD'):
                return
        except HTTPError as exc:
            if exc.code != 404:
                raise
        with self.request('blobs/uploads/', method='POST', data=b'') as response:
            location = response.headers['Location']
        location += ('&' if '?' in location else '?') + urlencode({'digest': digest})
        with self.request(location, method='PUT', data=data, content_type='application/octet-stream') as response:
            if response.headers.get('Docker-Content-Digest') != digest:
                raise ValueError('uploaded blob digest mismatch')

    def manifest(self, reference, data, media_type):
        digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        with self.request('manifests/' + reference, method='PUT', data=data, content_type=media_type) as response:
            if response.headers.get('Docker-Content-Digest') != digest:
                raise ValueError('uploaded manifest digest mismatch')
        # Re-fetch bytes: a tag or successful upload is not immutable proof.
        with self.request('manifests/' + digest) as response:
            if hashlib.sha256(response.read()).hexdigest() != digest[7:]:
                raise ValueError('registry changed manifest bytes')
        return digest


def checked_blob(layout, descriptor):
    digest = descriptor['digest']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('invalid descriptor digest')
    data = (layout / 'blobs/sha256' / digest[7:]).read_bytes()
    if hashlib.sha256(data).hexdigest() != digest[7:] or len(data) != descriptor['size']:
        raise ValueError('local OCI descriptor mismatch')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout', required=True, type=Path)
    parser.add_argument('--repository', required=True, help='lowercase owner/package, without registry')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*', args.repository) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', args.tag):
        raise ValueError('invalid repository/tag')
    layout = args.layout.resolve()
    index_data = (layout / 'index.json').read_bytes()
    index = json.loads(index_data)
    registry = Registry(args.repository)
    for descriptor in index['manifests']:
        data = checked_blob(layout, descriptor)
        manifest = json.loads(data)
        for blob in [manifest['config'], *manifest['layers']]:
            registry.blob(blob['digest'], checked_blob(layout, blob))
        registry.manifest(descriptor['digest'], data, descriptor['mediaType'])
    digest = registry.manifest(args.tag, index_data, index['mediaType'])
    registry.manifest('latest', index_data, index['mediaType'])
    result = {'image': 'ghcr.io/' + args.repository + '@' + digest, 'index_digest': digest, 'tag': args.tag}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['image'])


if __name__ == '__main__':
    main()
