#!/usr/bin/env python3
"""Install only repository-pinned cargo-dist bytes; never execute an installer.

Pins recorded from v0.33.0 release assets and checked against GitHub's asset
SHA-256 digests. These reviewed repository constants, NOT live upstream checksum
files, are the trust anchor for subsequent CI runs. Updating them needs review.
"""
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request
import zipfile

VERSION = '0.33.0'
SHA256 = {
    'aarch64-apple-darwin': '7b3cbe25511de01d74c0f5fcb7909edabd379bea9cfa284d93af5a3cdfa3247c',
    'x86_64-apple-darwin': '6a49bfb61bd86770d79c27f3d2b40c6b2e71cde940d3d31a6ccaaffc124d7a29',
    'aarch64-unknown-linux-musl': '4761cff5fc547ad66d1449abbf321380b0e6bd8093b1fe6593852a3314fd0c19',
    'x86_64-unknown-linux-musl': 'b8e95bc76c63375958173ef5ae2dbd8e9211cc1ed03cdee0899702766b4c2a2e',
    'x86_64-pc-windows-msvc': '9a36d70795e14326a5ec4bf17aee085df00ab85a322739291ea5d4b1b5f693cd',
}


def runner_target(system, machine):
    arch = {'AMD64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}[machine]
    suffix = {'Linux': 'unknown-linux-musl', 'Darwin': 'apple-darwin', 'Windows': 'pc-windows-msvc'}[system]
    target = f'{arch}-{suffix}'
    if target not in SHA256:
        raise ValueError(f'Unsupported dist bootstrap runner: {target}')
    return target


def verified_binary(archive, target):
    if hashlib.sha256(archive).hexdigest() != SHA256[target]:
        raise ValueError(f'cargo-dist {VERSION} SHA-256 mismatch for {target}')
    # Read just the executable, never extract arbitrary archive paths or links.
    root = f'cargo-dist-{target}'
    if target.endswith('windows-msvc'):
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            return package.read('dist.exe')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as package:
        member = package.getmember(f'{root}/dist')
        if not member.isfile():
            raise ValueError('dist archive executable is not a regular file')
        return package.extractfile(member).read()


def main():
    target = runner_target(platform.system(), platform.machine())
    extension = 'zip' if target.endswith('windows-msvc') else 'tar.xz'
    url = f'https://github.com/axodotdev/cargo-dist/releases/download/v{VERSION}/cargo-dist-{target}.{extension}'
    with urllib.request.urlopen(url, timeout=120) as response:
        binary = verified_binary(response.read(), target)
    destination = Path(os.environ['RUNNER_TEMP']) / 'wayfinder-dist'
    destination.mkdir(exist_ok=True)
    executable = destination / ('dist.exe' if extension == 'zip' else 'dist')
    with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
        output.write(binary)
        temporary = Path(output.name)
    temporary.chmod(0o755)
    temporary.replace(executable)
    with open(os.environ['GITHUB_PATH'], 'a', encoding='utf-8') as paths:
        paths.write(str(destination) + '\n')


if __name__ == '__main__':
    main()
