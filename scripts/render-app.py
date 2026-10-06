#!/usr/bin/env python3
"""Render a RouterOS manifest and custom catalog draft for an actual image digest.

Rendering does not publish the image/catalog or verify a registry upload. The
provided digest must equal the locally built two-platform index; tags are denied.
"""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def render(image, evidence):
    if not re.fullmatch(r'[a-z0-9][a-z0-9._:-]*/[a-z0-9._/-]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('explicit registry/repository at immutable digest required')
    if image.rsplit('@', 1)[1] != evidence['index_digest']:
        raise ValueError('image digest must match locally built multi-platform index')
    if set(evidence['platforms']) != {'amd64', 'arm64'}:
        raise ValueError('both built platforms required')
    template = (ROOT / 'packaging/routeros-app/app.yml').read_text()
    if template.count('REQUIRED_ACTUAL_IMAGE_AT_IMMUTABLE_DIGEST') != 1:
        raise ValueError('invalid application template')
    app = template.replace('REQUIRED_ACTUAL_IMAGE_AT_IMMUTABLE_DIGEST', image)
    return app, '-\n' + ''.join('  ' + line + '\n' for line in app.splitlines())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--build', type=Path, default=ROOT / '.cache/app-image/build.json')
    parser.add_argument('--out', type=Path, default=ROOT / '.cache/app-image')
    args = parser.parse_args()
    app, catalog = render(args.image, json.loads(args.build.read_text()))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'app.yml').write_text(app)
    (args.out / 'catalog.yml').write_text(catalog)
    print('Rendered app.yml and catalog.yml drafts; registry/catalog publication remains separate')
