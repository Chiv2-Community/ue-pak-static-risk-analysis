#!/usr/bin/env python3
"""Fail closed on rebuilt-image changes outside the reviewed source coverage."""

import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re

from collect_base_sources import RELEASE, inventory


def require(value):
    if not value:
        raise ValueError('rebuilt image metadata/source coverage mismatch; review the baseline before publication')


def doc_hash(docs, path):
    # Resolve metadata-only relative aliases; never follow a host/container link.
    for _ in range(20):
        parts = path.split('/')
        for i in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:i])
            entry = docs.get(prefix, {})
            if 'link' in entry:
                require(not entry['link'].startswith('/'))
                path = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), entry['link'], *parts[i:]))
                require(path != '..' and not path.startswith('../'))
                break
        else:
            return docs.get(path, {}).get('sha256')
    raise ValueError('documentation alias loop rejected')


def validate(actual, python_stage, baseline, sources):
    python_keys = {'python-version', 'pip-version', 'certifi-version', 'pip-vendor',
                   'pip-notices', 'pip-vendor-notices', 'python-docs'}
    require(set(python_stage) == python_keys)
    require(set(actual) == python_keys | {'ubuntu-packages', 'dotnet-versions', 'dlls', 'deps',
                                        'app-notices', 'dependency-notices', 'runtime-notices'})
    for key in ('python-version', 'dotnet-versions', 'dlls', 'pip-vendor'):
        require(actual[key] == baseline[key])
    require(sorted(actual['ubuntu-packages'], key=lambda p: p['Package']) ==
            sorted(baseline['ubuntu-packages'], key=lambda p: p['Package']))
    require(actual['pip-version'] == '25.0.1' and actual['certifi-version'] == '2024.8.30')
    require(actual['runtime-notices'] == baseline['runtime-notice-sha256'])
    for key in python_keys:
        require(actual[key] == python_stage[key])
    docs = actual['python-docs']
    for path, digest in baseline['python-spdx-copyright-sha256'].items():
        require(doc_hash(docs, path) == digest)
    # SPDX lists copyright files, not the whole doc tree. The full tree above
    # must equal the exact pinned Python stage; stop on unassociated directories.
    covered = {p.split('/')[0] for e in baseline['debian-doc-sources'] for p in
               [path.removeprefix('usr/share/doc/') for path in e['doc_paths']]}
    require(all(p.split('/')[0] in covered for p in docs))
    groups = {(e['group'], e['source'], e['version']) for e in sources}
    for p in actual['ubuntu-packages']:
        source = p['Source'] or p['Package']
        match = re.fullmatch(r'([^ ]+)(?: \(([^)]+)\))?', source)
        require(match is not None)
        require(('ubuntu', match[1], match[2] or p['Version']) in groups)
    for p in baseline['debian-doc-sources']:
        # Preserve SPDX's binNMU version separately from the descriptor-confirmed
        # source version. Never guess a source version from the binary at runtime.
        require(('debian-docs', p['source'], p['descriptor-source-version']) in groups)
    expected = {e['package'] + '/' + e['version'] for e in baseline['nuget']}
    found = {name for deps in actual['deps'].values() for name, value in deps['libraries'].items()
             if value['type'] == 'package'}
    require(found == expected)
    required = {'ue-pak-static-risk-analysis-GPL-3.0-only.txt', 'CORRESPONDING-SOURCE.md',
                'UAssetAPI-MIT.txt', 'UAssetAPI-NOTICE.md', 'Newtonsoft.Json-MIT.md'}
    require(required <= actual['app-notices'].keys())
    require(all(actual['app-notices'][name].get('bytes', 0) > 0 for name in required))
    require({'MIT.txt', 'README.md'} <= actual['dependency-notices'].keys())
    require(actual['pip-notices'] and actual['pip-vendor-notices'] and actual['runtime-notices'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual', type=Path, required=True)
    parser.add_argument('--python-stage', type=Path, required=True)
    args = parser.parse_args()
    baseline = json.loads((RELEASE / 'image-baseline.json').read_bytes())
    sources = inventory((RELEASE / 'source-inventory.json').read_bytes())
    actual = json.loads(args.actual.read_bytes())
    python_stage = json.loads(args.python_stage.read_bytes())
    validate(actual, python_stage, baseline, sources)
    dockerfile = (RELEASE.parents[1] / 'Dockerfile').read_text()
    require(re.findall(r'^FROM (\S+)', dockerfile, re.M) == baseline['base-images'])
    notices = actual['app-notices']
    for name, local in [('ue-pak-static-risk-analysis-GPL-3.0-only.txt', 'LICENSE'),
                        ('CORRESPONDING-SOURCE.md', 'container/CORRESPONDING-SOURCE.md'),
                        ('UAssetAPI-MIT.txt', 'vendor/UAssetAPI/LICENSE'),
                        ('UAssetAPI-NOTICE.md', 'vendor/UAssetAPI/NOTICE.md')]:
        require(notices[name]['sha256'] == hashlib.sha256((RELEASE.parents[1] / local).read_bytes()).hexdigest())
    for name in ('MIT.txt', 'README.md'):
        require(actual['dependency-notices'][name]['sha256'] == hashlib.sha256(
            (RELEASE.parents[1] / 'container/licenses' / name).read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
