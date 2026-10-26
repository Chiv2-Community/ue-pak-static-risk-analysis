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
        message, context = result.stderr.decode().splitlines()
        self.assertEqual('Source collection failed; no complete output published.', message)
        self.assertEqual('output', json.loads(context)['category'])

    def diagnostic_cli(self, mode):
        # Run the real CLI with only the HTTPS/filesystem boundary replaced.
        program = '''
import errno, hashlib, http.client, io, json, sys, urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch
import collect_base_sources as source
from test_base_sources import Response
root, mode = Path(sys.argv[1]), sys.argv[2]
source.RELEASE = root
canary = 'https://user:credential-canary@private.invalid/private-path'
entries = json.loads((root / 'inventory.json').read_text())
body = b'upstream source\\n'
dsc = ('Source: example\\nVersion: 1:1.0-1\\nChecksums-Sha256:\\n ' +
       entries[0]['sha256'] + ' ' + str(len(body)) + ' ' + entries[0]['filename'] + '\\n').encode()
if mode == 'descriptor':
    dsc = canary.encode()
    entries[1].update(size=len(dsc), sha256=hashlib.sha256(dsc).hexdigest())
if mode in {'schema', 'schema-late'}:
    entries[0 if mode == 'schema' else 1]['filename'] = canary
(root / 'source-inventory.json').write_text(json.dumps(entries))
def open_response(url, timeout):
    # Let the first sorted file finish, then fail the second.
    if url.endswith('.dsc'):
        return Response(dsc, url)
    if mode.startswith('http'):
        raise urllib.error.HTTPError(canary, int(mode[4:]), canary, {'Secret': canary}, io.BytesIO(canary.encode()))
    if mode == 'network':
        raise urllib.error.URLError(OSError(errno.ECONNRESET, canary))
    if mode == 'network-text':
        raise urllib.error.URLError(canary)
    if mode == 'timeout':
        raise urllib.error.URLError(TimeoutError(errno.ETIMEDOUT, canary))
    response = Response(body, url)
    if mode == 'short':
        response = Response(body[:-1], url)
    if mode == 'long':
        response = Response(body + b'x', url)
    if mode == 'hash':
        response = Response(b'x' * len(body), url)
    if mode == 'header':
        response.headers['Content-Length'] = canary
    if mode == 'encoding':
        response.headers['Content-Encoding'] = canary
    if mode == 'redirect':
        response.url = canary
    if mode == 'malformed-redirect':
        source.Redirects().redirect_request(source.urllib.request.Request(url), None, 302, canary, {}, 'https://[invalid')
    if mode.startswith('handler-redirect-'):
        code = int(mode.rsplit('-', 1)[1])
        handler = source.Redirects()
        headers = Message()
        headers['Location'] = 'https://[credential-canary'
        getattr(handler, 'http_error_' + str(code))(
            source.urllib.request.Request(url), response, code, canary, headers)
    if mode == 'read-timeout':
        response.read = lambda size: (_ for _ in ()).throw(TimeoutError(canary))
    if mode == 'read-incomplete':
        response.read = lambda size: (_ for _ in ()).throw(http.client.IncompleteRead(canary.encode()))
    if mode == 'status':
        response.status = 206
    return response
sys.argv = ['collect_base_sources.py', '--output', str(root / 'diagnostic-output')]
with patch.object(source.urllib.request.OpenerDirector, 'open', side_effect=open_response):
    if mode == 'output':
        with patch.object(Path, 'rename', side_effect=OSError(errno.ENOSPC, canary)):
            source.main()
    else:
        source.main()
'''
        scripts = str(Path(source.__file__).parent)
        tests = str(Path(__file__).resolve().parent)
        return subprocess.run([sys.executable, '-c',
                               'import sys; sys.path[:0] = ' + repr([scripts, tests]) + '\n' + program,
                               str(self.root), mode], capture_output=True, timeout=10)

    def test_cli_diagnostics_are_bounded_public_and_atomic(self):
        cases = {'http404': 'http', 'http429': 'http', 'network': 'network',
                 'network-text': 'network', 'timeout': 'timeout', 'read-timeout': 'timeout',
                 'read-incomplete': 'network',
                 'short': 'size', 'long': 'size', 'hash': 'hash', 'header': 'header',
                 'encoding': 'header', 'redirect': 'redirect', 'malformed-redirect': 'redirect',
                 'status': 'http', 'descriptor': 'descriptor', 'output': 'output',
                 'schema': 'schema', 'schema-late': 'schema'}
        for mode, category in cases.items():
            with self.subTest(mode=mode):
                result = self.diagnostic_cli(mode)
                self.assertEqual(1, result.returncode)
                self.assertEqual(b'', result.stdout)
                self.assertLess(len(result.stderr), 1024)
                self.assertNotIn(b'credential-canary', result.stderr)
                self.assertNotIn(b'private', result.stderr)
                self.assertNotIn(str(self.root).encode(), result.stderr)
                message, raw = result.stderr.decode().splitlines()
                self.assertEqual('Source collection failed; no complete output published.', message)
                context = json.loads(raw)
                self.assertEqual(category, context['category'])
                expected = {'stage', 'ordinal', 'total', 'completed_files', 'completed_bytes', 'category'}
                if mode in {'schema', 'schema-late'}:
                    self.assertEqual('prevalidation', context['stage'])
                    self.assertEqual((0, 0, 0, 0), tuple(context[k] for k in
                                     ('ordinal', 'total', 'completed_files', 'completed_bytes')))
                else:
                    self.assertEqual(2, context['total'])
                    complete = mode in {'descriptor', 'output'}
                    self.assertEqual(2 if complete else 1, context['completed_files'])
                    descriptor_size = (len('https://user:credential-canary@private.invalid/private-path')
                                       if mode == 'descriptor' else len(self.dsc))
                    self.assertEqual(descriptor_size + (len(self.body) if complete else 0), context['completed_bytes'])
                    self.assertEqual('descriptors' if mode == 'descriptor' else
                                     'bundle' if mode == 'output' else 'fetch', context['stage'])
                    if mode != 'output':
                        expected.add('entry')
                        entry = self.descriptor if mode == 'descriptor' else self.entry
                        self.assertEqual({k: entry[k] for k in ('group', 'source', 'version', 'filename')},
                                         context['entry'])
                        self.assertEqual(1 if mode == 'descriptor' else 2, context['ordinal'])
                if mode.startswith('http') or mode == 'status':
                    expected.add('http_status')
                    self.assertEqual(int(mode[4:]) if mode.startswith('http') else 206, context['http_status'])
                if mode in {'network', 'timeout'}:
                    import errno
                    expected.add('errno')
                    self.assertEqual(errno.ECONNRESET if mode == 'network' else errno.ETIMEDOUT, context['errno'])
                self.assertEqual(expected, set(context))
                self.assertFalse((self.root / 'diagnostic-output').exists())
                self.assertEqual([], list(self.root.glob('.base-source-*')))

    def test_cli_malformed_redirect_handler_aliases_are_safe_and_atomic(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                result = self.diagnostic_cli('handler-redirect-' + str(code))
                self.assertEqual(1, result.returncode)
                self.assertEqual(b'', result.stdout)
                self.assertLess(len(result.stderr), 1024)
                self.assertNotIn(b'credential-canary', result.stderr)
                self.assertNotIn(b'private', result.stderr)
                self.assertNotIn(str(self.root).encode(), result.stderr)
                message, raw = result.stderr.decode().splitlines()
                self.assertEqual('Source collection failed; no complete output published.', message)
                self.assertEqual({
                    'stage': 'fetch', 'ordinal': 2, 'total': 2,
                    'completed_files': 1, 'completed_bytes': len(self.dsc),
                    'category': 'redirect',
                    'entry': {k: self.entry[k] for k in ('group', 'source', 'version', 'filename')},
                }, json.loads(raw))
                self.assertFalse((self.root / 'diagnostic-output').exists())
                self.assertEqual([], list(self.root.glob('.base-source-*')))

    def test_open_preserves_source_error_categories_and_details(self):
        for category in ('schema', 'http', 'network', 'timeout', 'size', 'header',
                         'hash', 'redirect', 'descriptor', 'output'):
            error = source.SourceError(category, http_status=429)
            with self.subTest(category=category), patch.object(
                    urllib.request.OpenerDirector, 'open', side_effect=error):
                with self.assertRaises(source.SourceError) as caught:
                    source.fetch(self.entry, self.root / 'unused', urllib.request.build_opener())
                self.assertIs(error, caught.exception)
                self.assertEqual(category, caught.exception.category)
                self.assertEqual({'http_status': 429}, caught.exception.details)

    def test_maximum_validated_context_is_bounded(self):
        entry = dict(self.entry, source='a' * 100, version='b' * 100, filename='c' * 200)
        self.manifest.write_text(json.dumps([entry]))
        with patch.object(urllib.request.OpenerDirector, 'open', side_effect=TimeoutError('credential-canary')):
            with self.assertRaises(source.SourceError) as caught:
                source.collect(self.manifest, self.readme, self.root / 'maximum')
        context = caught.exception.context
        self.assertEqual('timeout', context['category'])
        self.assertEqual({k: entry[k] for k in ('group', 'source', 'version', 'filename')}, context['entry'])
        self.assertLess(len(json.dumps(context, ensure_ascii=True)), 900)
        self.assertNotIn('credential-canary', json.dumps(context))
        self.assertFalse((self.root / 'maximum').exists())
        self.assertEqual([], list(self.root.glob('.base-source-*')))

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
