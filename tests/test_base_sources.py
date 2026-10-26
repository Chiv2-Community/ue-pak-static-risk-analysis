"""Bounded offline source collection using tiny fake HTTPS responses."""

import hashlib
import io
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import collect_base_sources as source

TEMP = '/tmp/opencode' if Path('/tmp/opencode').is_dir() else None


class Response(io.BytesIO):
    status = 200

    def __init__(self, body, url, length=None):
        super().__init__(body)
        self.url = url
        self.headers = {} if length is None else {'Content-Length': length}

    def geturl(self):
        return self.url


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEMP, prefix='base-source-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.body = b'upstream source\n'
        self.entry = dict(group='ubuntu', source='example', version='1:1.0-1',
                          filename='example_1.0.orig.tar.xz', size=len(self.body),
                          sha256=hashlib.sha256(self.body).hexdigest(),
                          url='https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/example/1:1.0-1/example_1.0.orig.tar.xz')
        self.dsc = ('Source: example\nVersion: 1:1.0-1\nChecksums-Sha256:\n ' + self.entry['sha256'] +
                    ' ' + str(len(self.body)) + ' ' + self.entry['filename'] + '\n').encode()
        self.descriptor = dict(self.entry, filename='example_1.0-1.dsc', size=len(self.dsc),
                               sha256=hashlib.sha256(self.dsc).hexdigest(),
                               url=self.entry['url'].replace(self.entry['filename'], 'example_1.0-1.dsc'))
        self.entries = [self.entry, self.descriptor]
        self.manifest = self.root / 'inventory.json'
        self.manifest.write_text(json.dumps(self.entries))
        self.readme = self.root / 'README.md'
        self.readme.write_text('Build instructions\n')

    def open(self, url, timeout):
        self.assertEqual(30, timeout)
        return Response(self.dsc if url.endswith('.dsc') else self.body, url)

    def collect(self, output):
        with patch.object(urllib.request.OpenerDirector, 'open', side_effect=self.open):
            source.collect(self.manifest, self.readme, output)

    def test_deterministic_complete_bundle_exact_manifest_and_checksums(self):
        self.collect(self.root / 'one')
        self.collect(self.root / 'two')
        self.assertEqual((self.root / 'one/base-source.tar').read_bytes(), (self.root / 'two/base-source.tar').read_bytes())
        with tarfile.open(self.root / 'one/base-source.tar') as tar:
            self.assertEqual(5, len(tar.getmembers()))
            self.assertTrue(all(m.isfile() and m.mtime == m.uid == m.gid == 0 for m in tar))
            self.assertEqual(self.manifest.read_bytes(), tar.extractfile('source-inventory.json').read())
        for line in (self.root / 'one/SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, hashlib.sha256((self.root / 'one' / name).read_bytes()).hexdigest())

    def test_untrusted_urls_and_redirect_targets_rejected(self):
        bad = ['http://launchpad.net/file', 'https://user:secret@launchpad.net/file',
               'https://launchpad.net:443/file', 'https://launchpad.net.evil/file',
               'https://snapshot.debian.org/file/' + 'a' * 40 + '?key=secret',
               'https://snapshot.debian.org/file/' + 'a' * 40 + '#x',
               'https://launchpadlibrarian.net/1/../key',
               'https://launchpadlibrarian.net/1/%2e%2e', 'https://localhost/key',
               'https://launchpadlibrarian.net/1/a\\b']
        handler = source.Redirects()
        request = urllib.request.Request(self.entry['url'])
        for url in bad:
            with self.subTest(url=url), self.assertRaises(ValueError):
                source.url_allowed(url)
            with self.subTest(redirect=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'Found', {}, url)
        self.assertIsNotNone(handler.redirect_request(request, None, 302, 'Found', {},
                              'https://launchpadlibrarian.net/123/example.tar.xz'))

    def test_strict_entries_sizes_duplicates_and_aggregate(self):
        for field, value in [('extra', 'x'), ('group', 'other'), ('source', '../secret'),
                             ('version', '../../x'), ('filename', '/key'), ('size', True),
                             ('size', -1), ('size', source.FILE_LIMIT + 1), ('sha256', 'x'), ('url', 7)]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                source.inventory(json.dumps([dict(self.entry, **{field: value})]).encode())
        for raw in (json.dumps([self.entry, self.entry]).encode(), b'{}', b'[]',
                    b'[{"group":"ubuntu","group":"ubuntu"}]', b'x' * (1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                source.inventory(raw)
        with patch.object(source, 'LIMIT', 1), self.assertRaises(ValueError):
            source.inventory(self.manifest.read_bytes())

    def test_response_failures_never_leave_completed_output(self):
        for mode in ('short', 'long', 'digest', 'length', 'encoding', 'redirect', 'timeout', 'status'):
            def open_response(url, timeout):
                body = self.dsc if url.endswith('.dsc') else self.body
                if mode == 'timeout':
                    raise TimeoutError('fixture')
                response = Response(body[:-1] if mode == 'short' else body + b'x' if mode == 'long' else
                                    b'x' * len(body) if mode == 'digest' else body, url,
                                    '999' if mode == 'length' else None)
                if mode == 'encoding':
                    response.headers['Content-Encoding'] = 'gzip'
                if mode == 'redirect':
                    response.url = 'https://evil.example/key'
                if mode == 'status':
                    response.status = 206
                return response
            output = self.root / mode
            with patch.object(urllib.request.OpenerDirector, 'open', side_effect=open_response):
                with self.assertRaises((ValueError, TimeoutError)):
                    source.collect(self.manifest, self.readme, output)
            self.assertFalse(output.exists())
            self.assertEqual([], list(self.root.glob('.base-source-*')))

    def test_existing_output_symlinks_and_descriptor_omission_rejected(self):
        output = self.root / 'existing'
        output.mkdir()
        with self.assertRaises(ValueError):
            self.collect(output)
        link = self.root / 'link'
        link.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError):
            self.collect(link)
        parent = self.root / 'parent'
        parent.symlink_to(output)
        with self.assertRaises(ValueError):
            self.collect(parent / 'child')
        self.manifest.write_text(json.dumps([self.entry]))
        with self.assertRaises(ValueError):
            self.collect(self.root / 'incomplete')
        self.assertFalse((self.root / 'incomplete').exists())

    def test_partial_download_failure_and_cli_error_are_bounded(self):
        def partial(url, timeout):
            return Response(self.dsc if url.endswith('.dsc') else b'corrupt', url)
        with patch.object(urllib.request.OpenerDirector, 'open', side_effect=partial):
            with self.assertRaises(ValueError):
                source.collect(self.manifest, self.readme, self.root / 'partial')
        self.assertFalse((self.root / 'partial').exists())
        self.assertEqual([], list(self.root.glob('.base-source-*')))
        result = subprocess.run([sys.executable, source.__file__, '--output', str(self.root)],
                                capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertEqual(b'Source collection failed; no complete output published.\n', result.stderr)

    def test_committed_inventory_exact_audited_coverage(self):
        entries = source.inventory((source.RELEASE / 'source-inventory.json').read_bytes())
        self.assertEqual(459, len(entries))
        self.assertEqual(647494595, sum(e['size'] for e in entries))
        for group, count in [('ubuntu', 69), ('debian-docs', 73)]:
            files = [e for e in entries if e['group'] == group]
            self.assertEqual(count, len({(e['source'], e['version']) for e in files}))
            self.assertEqual(count, sum(e['filename'].endswith('.dsc') for e in files))


if __name__ == '__main__':
    unittest.main()
