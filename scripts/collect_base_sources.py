#!/usr/bin/env python3
"""Fetch the reviewed public source inventory; never extract or execute sources."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

LIMIT = 800 * 1024 * 1024
FILE_LIMIT = 128 * 1024 * 1024
RELEASE = Path(__file__).resolve().parents[1] / 'releases/v0.1.0'


def require(value):
    if not value:
        raise ValueError('source collection input or response rejected')


def url_allowed(url):
    require(isinstance(url, str) and len(url) <= 1024)
    p = urllib.parse.urlsplit(url)
    require(p.scheme == 'https' and not p.username and not p.password and
            p.port is None and not p.query and not p.fragment and
            p.netloc == p.hostname and not re.search(r'[\s\\%]', url))
    patterns = {
        'launchpad.net': r'/ubuntu/\+archive/primary/\+sourcefiles/[a-z0-9+.-]+/[A-Za-z0-9.+:~_-]+/[A-Za-z0-9.+~_-]+',
        'launchpadlibrarian.net': r'/[0-9]+/[A-Za-z0-9.+~_-]+',
        'snapshot.debian.org': r'/file/[a-f0-9]{40}',
        'www.python.org': r'/ftp/python/3\.12\.14/Python-3\.12\.14.tar.xz',
        'files.pythonhosted.org': r'/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{60}/[A-Za-z0-9.+_-]+',
    }
    require(p.hostname in patterns and re.fullmatch(patterns[p.hostname], p.path) and
            all(part not in {'.', '..'} for part in p.path.split('/')))
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, url_allowed(newurl))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def inventory(raw):
    require(len(raw) <= 1024 * 1024)
    entries = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(entries, list) and 0 < len(entries) <= 600)
    paths = set()
    total = 0
    for e in entries:
        require(isinstance(e, dict) and set(e) == {'group', 'source', 'version', 'filename', 'url', 'size', 'sha256'})
        require(all(isinstance(e[k], str) for k in e if k != 'size'))
        require(e['group'] in {'ubuntu', 'debian-docs', 'python'})
        for key, pattern in [('source', r'[a-z0-9][a-z0-9+.-]{0,99}'),
                             ('version', r'[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,99}'),
                             ('filename', r'[A-Za-z0-9][A-Za-z0-9.+~_-]{0,199}')]:
            require(re.fullmatch(pattern, e[key]) and e[key] not in {'.', '..'})
        require(re.fullmatch(r'[a-f0-9]{64}', e['sha256']))
        require(type(e['size']) is int and 0 < e['size'] <= FILE_LIMIT)
        url_allowed(e['url'])
        path = '/'.join(e[k] for k in ('group', 'source', 'version', 'filename'))
        require(path not in paths)
        paths.add(path)
        total += e['size']
    require(total <= LIMIT)
    return sorted(entries, key=lambda e: tuple(e[k] for k in ('group', 'source', 'version', 'filename')))


def fetch(entry, output, opener):
    deadline = time.monotonic() + 300
    digest, size = hashlib.sha256(), 0
    with opener.open(url_allowed(entry['url']), timeout=30) as response:
        require(response.status == 200)
        url_allowed(response.geturl())
        length = response.headers.get('Content-Length')
        require(length is None or length == str(entry['size']))
        require(response.headers.get('Content-Encoding', 'identity') == 'identity')
        with output.open('xb') as target:
            while True:
                require(time.monotonic() < deadline)
                chunk = response.read(min(65536, entry['size'] - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= entry['size'])
                digest.update(chunk)
                target.write(chunk)
    require(size == entry['size'] and digest.hexdigest() == entry['sha256'])


def descriptors(entries, payload):
    groups = {}
    for e in entries:
        groups.setdefault((e['group'], e['source'], e['version']), []).append(e)
    for (group, source, version), files in groups.items():
        if group == 'python':
            continue
        dsc = [e for e in files if e['filename'].endswith('.dsc')]
        require(len(dsc) == 1 and dsc[0]['size'] <= 65536)
        raw = (payload / group / source / version / dsc[0]['filename']).read_text()
        require(re.search(r'^Source: ' + re.escape(source) + r'$', raw, re.M))
        require(re.search(r'^Version: ' + re.escape(version) + r'$', raw, re.M))
        match = re.search(r'^Checksums-Sha256:\n((?: .+\n)+)', raw, re.M)
        require(match is not None)
        declared = {}
        for line in match[1].splitlines():
            digest, size, filename = line.split()
            require(filename not in declared)
            declared[filename] = (digest, int(size))
        require(declared == {e['filename']: (e['sha256'], e['size']) for e in files if e not in dsc})


def collect(manifest, readme, output):
    # A newly created output directory is the transaction boundary. Never touch
    # existing files, including dangling links. Failures leave no complete bundle.
    require(not manifest.is_symlink() and manifest.stat().st_size <= 1024 * 1024)
    require(not readme.is_symlink() and readme.stat().st_size <= 1024 * 1024)
    require(output.parent.absolute() == output.parent.resolve(strict=True))
    raw = manifest.read_bytes()
    entries = inventory(raw)
    require(not output.exists() and not output.is_symlink())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirects())
    with tempfile.TemporaryDirectory(prefix='.base-source-', dir=output.parent) as temporary:
        root = Path(temporary)
        payload = root / 'payload'
        payload.mkdir()
        checksums = []
        for e in entries:
            path = '/'.join(e[k] for k in ('group', 'source', 'version', 'filename'))
            local = payload / path
            local.parent.mkdir(parents=True, exist_ok=True)
            fetch(e, local, opener)
            checksums.append(e['sha256'] + '  ' + path + '\n')
        descriptors(entries, payload)
        (payload / 'source-inventory.json').write_bytes(raw)
        (payload / 'README.md').write_bytes(readme.read_bytes())
        (payload / 'SHA256SUMS').write_text(''.join(checksums))
        result = root / 'result'
        result.mkdir()
        with tarfile.open(result / 'base-source.tar', 'w', format=tarfile.PAX_FORMAT) as tar:
            for p in sorted(payload.rglob('*')):
                if p.is_file():
                    info = tarfile.TarInfo(p.relative_to(payload).as_posix())
                    info.size, info.mode, info.mtime = p.stat().st_size, 0o644, 0
                    with p.open('rb') as data:
                        tar.addfile(info, data)
        (result / 'source-inventory.json').write_bytes(raw)
        (result / 'README.md').write_bytes(readme.read_bytes())
        lines = []
        for p in sorted(result.iterdir()):
            with p.open('rb') as data:
                lines.append(hashlib.file_digest(data, 'sha256').hexdigest() + '  ' + p.name + '\n')
        (result / 'SHA256SUMS').write_text(''.join(lines))
        require(not output.exists() and not output.is_symlink())
        result.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        collect(RELEASE / 'source-inventory.json', RELEASE / 'README.md', args.output)
    except (OSError, ValueError, TimeoutError, RecursionError):
        parser.exit(1, 'Source collection failed; no complete output published.\n')


if __name__ == '__main__':
    main()
