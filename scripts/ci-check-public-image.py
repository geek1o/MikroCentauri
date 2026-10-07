#!/usr/bin/env python3
"""Require an anonymous verified image pull before publishing an App Store catalog."""
import argparse
import hashlib
import json
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from pathlib import Path


def verify(image, output=None):
    match = re.fullmatch(r'ghcr\.io/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)@(sha256:[0-9a-f]{64})', image)
    if not match:
        raise ValueError('exact GHCR image digest required')
    repository, digest = match.groups()
    query = urlencode({'service': 'ghcr.io', 'scope': 'repository:' + repository + ':pull'})
    try:
        with urlopen('https://ghcr.io/token?' + query, timeout=60) as response:
            token = json.load(response)['token']
        def manifest(reference):
            request = Request('https://ghcr.io/v2/' + repository + '/manifests/' + reference,
                              headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json'})
            with urlopen(request, timeout=60) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != reference[7:]:
                raise ValueError('anonymous registry manifest digest mismatch')
            return json.loads(data)
        index = manifest(digest)
        if {d['platform']['architecture'] for d in index['manifests']} != {'amd64', 'arm64'}:
            raise ValueError('both supported image platforms required')
        for descriptor in index['manifests']:
            platform = manifest(descriptor['digest'])
            for blob in [platform['config'], *platform['layers']]:
                request = Request('https://ghcr.io/v2/' + repository + '/blobs/' + blob['digest'], method='HEAD',
                                  headers={'Authorization': 'Bearer ' + token})
                with urlopen(request, timeout=60) as response:
                    if int(response.headers.get('Content-Length', '-1')) != blob['size']:
                        raise ValueError('anonymous image blob size mismatch')
    except HTTPError as exc:
        if exc.code in {401, 403, 404}:
            owner, package = repository.split('/', 1)
            if output:
                output.write_text(json.dumps({'image': image, 'anonymous_pull_verified': False, 'catalog_publication_allowed': False}, indent=2) + '\n')
            raise SystemExit('App Store publication blocked: image is not anonymously downloadable. Open https://github.com/' + owner + '?tab=packages, select ' + package + ', open Package settings and change visibility to Public, then rerun this workflow. Repository visibility is independent.') from None
        raise
    print('Anonymous immutable image pull verified:', image)
    if output:
        output.write_text(json.dumps({'image': image, 'anonymous_pull_verified': True, 'catalog_publication_allowed': True}, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    verify(args.image, args.output)
