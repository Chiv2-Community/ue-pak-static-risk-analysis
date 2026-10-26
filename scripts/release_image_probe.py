#!/usr/bin/env python3
"""Read only fixed public image metadata; no environment or user inputs."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def tree(root):
    root = Path(root)
    assert root.is_dir() and not root.is_symlink()
    result = {}
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            p = Path(directory) / name
            relative = p.relative_to(root).as_posix()
            mode = p.lstat().st_mode
            if stat.S_ISLNK(mode):
                # Record links as text, never read through them or copy targets.
                result[relative] = {'link': os.readlink(p)}
            elif stat.S_ISREG(mode):
                size = p.stat().st_size
                assert size <= 16 * 1024 * 1024
                total += size
                assert total <= 64 * 1024 * 1024
                with p.open('rb') as source:
                    result[relative] = {'bytes': size, 'sha256': hashlib.file_digest(source, 'sha256').hexdigest()}
            else:
                assert stat.S_ISDIR(mode)
            assert len(result) <= 5000
    return result


def probe(python_stage=False):
    site = Path('/usr/local/lib/python3.12/site-packages')
    pip_notice = tree(site / 'pip-25.0.1.dist-info')
    vendor = tree(site / 'pip/_vendor')
    vendor = {p: v for p, v in vendor.items() if 'license' in p.lower() or 'copying' in p.lower() or p.endswith('vendor.txt')}
    assert pip_notice and vendor
    result = {'python-version': '.'.join(map(str, sys.version_info[:3])),
              'pip-version': __import__('pip').__version__,
              'certifi-version': __import__('pip._vendor.certifi', fromlist=['__version__']).__version__,
              'pip-vendor': (site / 'pip/_vendor/vendor.txt').read_text(),
              'pip-notices': pip_notice, 'pip-vendor-notices': vendor,
              'python-docs': tree('/usr/share/doc' if python_stage else '/licenses/python-os')}
    if python_stage:
        return result
    packages = []
    for paragraph in Path('/var/lib/dpkg/status').read_text().split('\n\n'):
        fields = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ': ' in line:
                key, value = line.split(': ', 1)
                fields[key] = value
        if fields.get('Status') == 'install ok installed':
            packages.append({key: fields.get(key, '') for key in ('Package', 'Version', 'Source', 'Architecture')})
    result['ubuntu-packages'] = sorted(packages, key=lambda p: p['Package'])
    result['dotnet-versions'] = {str(p): p.read_text() for p in sorted(Path('/usr/share/dotnet/shared/Microsoft.NETCore.App').glob('*/.version'))}
    result['dlls'] = sorted(str(p) for p in Path('/app').rglob('*.dll'))
    result['deps'] = {str(p): json.loads(p.read_bytes()) for p in
                      (Path('/app/parser/Parser.deps.json'), Path('/app/evaluator/Scanner.deps.json'))}
    result['app-notices'] = tree('/app/licenses')
    result['dependency-notices'] = tree('/licenses/dependencies')
    result['runtime-notices'] = {}
    required = ['/usr/local/lib/python3.12/LICENSE.txt', '/usr/share/dotnet/LICENSE.txt',
                '/usr/share/dotnet/ThirdPartyNotices.txt']
    required += ['/usr/share/doc/' + p['Package'] + '/copyright' for p in packages]
    for path in required:
        # Ubuntu copyright aliases are expected; constrain resolution to doc root.
        p = Path(path)
        resolved = p.resolve(strict=True)
        assert resolved.is_relative_to('/usr/share/doc') if path.startswith('/usr/share/doc/') else resolved == p
        assert 0 < resolved.stat().st_size <= 2 * 1024 * 1024
        result['runtime-notices'][path] = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return result


if __name__ == '__main__':
    raw = json.dumps(probe(sys.argv[1:] == ['--python-stage']), sort_keys=True).encode()
    assert len(raw) <= 2 * 1024 * 1024
    sys.stdout.buffer.write(raw + b'\n')
