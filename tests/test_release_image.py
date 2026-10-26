"""Offline rebuilt-image gate and bounded metadata traversal fixtures."""

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import collect_base_sources as source
import release_image_probe as probe
import release_record
import validate_release_image as validator

TEMP = '/tmp/opencode' if Path('/tmp/opencode').is_dir() else None


class ImageGateTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads((source.RELEASE / 'image-baseline.json').read_bytes())
        self.sources = source.inventory((source.RELEASE / 'source-inventory.json').read_bytes())
        self.actual = {key: copy.deepcopy(self.baseline[key]) for key in
                       ('python-version', 'dotnet-versions', 'dlls', 'pip-vendor', 'ubuntu-packages')}
        self.actual.update({'pip-version': '25.0.1', 'certifi-version': '2024.8.30',
                            'pip-notices': {'LICENSE.txt': {'sha256': 'a' * 64}},
                            'pip-vendor-notices': {'certifi/LICENSE': {'sha256': 'b' * 64}},
                            'runtime-notices': copy.deepcopy(self.baseline['runtime-notice-sha256']),
                            'python-docs': {p: {'sha256': h} for p, h in self.baseline['python-spdx-copyright-sha256'].items()},
                            'app-notices': {p: {'sha256': 'd' * 64, 'bytes': 1} for p in
                                ['ue-pak-static-risk-analysis-GPL-3.0-only.txt', 'CORRESPONDING-SOURCE.md',
                                 'UAssetAPI-MIT.txt', 'UAssetAPI-NOTICE.md', 'Newtonsoft.Json-MIT.md']},
                            'dependency-notices': {'MIT.txt': {}, 'README.md': {}},
                            'deps': {'/app/parser/Parser.deps.json': {'libraries': {
                                e['package'] + '/' + e['version']: {'type': 'package'} for e in self.baseline['nuget']}}}})
        self.python = {key: copy.deepcopy(self.actual[key]) for key in
                       ('python-version', 'pip-version', 'certifi-version', 'pip-vendor', 'pip-notices', 'pip-vendor-notices', 'python-docs')}

    def validate(self):
        validator.validate(self.actual, self.python, self.baseline, self.sources)

    def test_exact_metadata_and_source_coverage_accepts(self):
        self.validate()

    def test_new_image_version_source_dll_vendor_and_dependency_drift_stops(self):
        mutations = [lambda a: a.update({'python-version': '3.12.99'}),
                     lambda a: a['ubuntu-packages'][0].update(Source='wrong-source (1.0)'),
                     lambda a: a['ubuntu-packages'][0].update(Version='99'),
                     lambda a: a['dlls'].append('/app/parser/Unknown.dll'),
                     lambda a: a['dotnet-versions'].update({'/unknown': 'changed'}),
                     lambda a: a.update({'pip-vendor': 'changed'}),
                     lambda a: a['app-notices'].pop('UAssetAPI-MIT.txt'),
                     lambda a: a['dependency-notices'].pop('MIT.txt'),
                     lambda a: a['deps']['/app/parser/Parser.deps.json']['libraries'].update({'Unknown/1.0': {'type': 'package'}}),
                     lambda a: a['python-docs'].update({'unknown/README': {'sha256': 'a' * 64}})]
        original = copy.deepcopy(self.actual)
        for mutate in mutations:
            self.actual = copy.deepcopy(original)
            mutate(self.actual)
            with self.assertRaises(ValueError):
                self.validate()

    def test_docs_full_tree_equality_and_spdx_hashes_are_both_required(self):
        self.actual['python-docs']['apt/new-file'] = {'sha256': 'e' * 64}
        with self.assertRaises(ValueError):
            self.validate()
        self.python['python-docs'] = copy.deepcopy(self.actual['python-docs'])
        self.validate()
        self.actual['python-docs']['apt/copyright'] = {'sha256': 'f' * 64}
        self.python['python-docs'] = copy.deepcopy(self.actual['python-docs'])
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_source_version_stops(self):
        self.sources = [e for e in self.sources if e['source'] != 'apt']
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_python_stage_evidence_is_not_vacuous_equality(self):
        for value in ({}, {k: v for k, v in self.python.items() if k != 'python-docs'}):
            with self.assertRaises(ValueError):
                validator.validate(self.actual, value, self.baseline, self.sources)

    def test_doc_aliases_stay_in_metadata_tree(self):
        docs = {'one': {'link': 'two'}, 'two/copyright': {'sha256': 'hash'}}
        self.assertEqual('hash', validator.doc_hash(docs, 'one/copyright'))
        for target in ('../outside', '/etc', 'one'):
            docs['one']['link'] = target
            with self.assertRaises(ValueError):
                validator.doc_hash(docs, 'one/copyright')

    def test_probe_records_not_follows_symlinks_and_bounds_files(self):
        with tempfile.TemporaryDirectory(dir=TEMP, prefix='probe-tree-') as temporary:
            root = Path(temporary)
            (root / 'notice').write_bytes(b'copyright')
            (root / 'external').symlink_to('/private/not-readable')
            (root / 'directory').symlink_to('/private/directory')
            result = probe.tree(root)
            self.assertEqual({'link': '/private/not-readable'}, result['external'])
            self.assertEqual(hashlib.sha256(b'copyright').hexdigest(), result['notice']['sha256'])
            (root / 'oversized').touch()
            with (root / 'oversized').open('wb') as output:
                output.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(AssertionError):
                probe.tree(root)

    def test_unpublished_record_pending_digest_and_complete_transfer_hashes(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory(dir=TEMP, prefix='release-record-') as temporary:
            root = Path(temporary) / 'candidate'
            root.mkdir()
            (root / 'base-sources').mkdir()
            for name in ('base-sources/base-source.tar', 'base-sources/source-inventory.json',
                         'image.tar.gz', 'image-baseline.json'):
                (root / name).write_bytes(b'fixture')
            (root / 'image-id.txt').write_text('sha256:' + 'a' * 64 + '\n')
            (root / 'docker-version.txt').write_text('1/1\n')
            (root / 'image-metadata.json').write_text(json.dumps(self.actual))
            (root / 'python-stage-metadata.json').write_text(json.dumps(self.python))
            manifest = {'build-source': 'b' * 40, 'action-source': 'b' * 40,
                        'uassetapi-source': 'c' * 40, 'files': []}
            raw = json.dumps(manifest).encode()
            with tarfile.open(root / 'source.tar.gz', 'w:gz') as archive:
                entry = tarfile.TarInfo('ue-pak-static-risk-analysis/SOURCE-MANIFEST.json')
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
            with patch.dict(os.environ, {'RUNNER_TEMP': temporary, 'SOURCE': 'b' * 40, 'RUN_ID': '1', 'RUN_ATTEMPT': '1'}):
                release_record.main()
            record = json.loads((root / 'build-record.json').read_bytes())
            self.assertEqual('PENDING', record['image'])
            self.assertIn('base-sources/base-source.tar', record['artifact-sha256'])
            sums = (root / 'SHA256SUMS').read_text().splitlines()
            self.assertEqual(len([p for p in root.rglob('*') if p.is_file()]) - 1, len(sums))
            for line in sums:
                digest, name = line.split('  ')
                self.assertEqual(digest, hashlib.sha256((root / name).read_bytes()).hexdigest())
            (root / 'foreign-link').symlink_to('/private/unknown')
            with self.assertRaises(ValueError):
                release_record.checksums(root)


if __name__ == '__main__':
    unittest.main()
