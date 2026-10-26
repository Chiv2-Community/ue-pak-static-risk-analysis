#!/usr/bin/env python3
"""Record only allowlisted public build identities and artifact hashes."""

import hashlib
import json
import os
from pathlib import Path
import re
import tarfile

from collect_base_sources import RELEASE, require


def digest(path):
    with path.open('rb') as data:
        return hashlib.file_digest(data, 'sha256').hexdigest()


def checksums(root):
    paths = sorted(p for p in root.rglob('*') if p.is_file() and p != root / 'SHA256SUMS')
    require(not any(p.is_symlink() for p in root.rglob('*')))
    (root / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + p.relative_to(root).as_posix() + '\n' for p in paths))


def main():
    root = Path(os.environ['RUNNER_TEMP']) / 'candidate'
    source = os.environ['SOURCE']
    require(re.fullmatch(r'[a-f0-9]{40}', source))
    with tarfile.open(root / 'source.tar.gz') as archive:
        entry = archive.getmember('ue-pak-static-risk-analysis/SOURCE-MANIFEST.json')
        require(entry.isfile() and entry.size <= 2 * 1024 * 1024)
        raw = archive.extractfile(entry).read()
    manifest = json.loads(raw)
    require(manifest['build-source'] == source and manifest['action-source'] == source)
    baseline = json.loads((RELEASE / 'image-baseline.json').read_bytes())
    actual = json.loads((root / 'image-metadata.json').read_bytes())
    image_id = (root / 'image-id.txt').read_text().strip()
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id))
    record = {'version': 'v0.1.0-candidate', 'build-source': source, 'action-source': source,
              'platform': 'linux/amd64', 'image': 'PENDING', 'image-id': image_id,
              'run-id': os.environ['RUN_ID'], 'run-attempt': os.environ['RUN_ATTEMPT'],
              'source-manifest-sha256': hashlib.sha256(raw).hexdigest(),
              'uassetapi-source': manifest['uassetapi-source'],
              'base-images': baseline['base-images'],
              'lockfiles': [f for f in manifest['files'] if f['path'].endswith('packages.lock.json')],
              'ubuntu-packages': actual['ubuntu-packages'],
              'docker-client-server-version': (root / 'docker-version.txt').read_text().strip(),
              'artifact-sha256': {name: digest(root / name) for name in
                  ['source.tar.gz', 'dependency-source-inventory.json',
                    'image-metadata.json', 'python-stage-metadata.json', 'image-baseline.json']},
              'dependency-source-delivery': 'upstream links only; not mirrored or availability-certified',
              'source-delivery': 'authenticated three-day staging only; durable public assets pending',
              'public-unauthenticated-pull': 'pending-operator-verification'}
    (root / 'build-record.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    checksums(root)


if __name__ == '__main__':
    main()
