#!/usr/bin/env python3
"""Offline integrity regression tests, plus optional real pinned-asset checks."""
import hashlib
import io
import tarfile
import zipfile
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).with_name('dist-bootstrap.py'))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def test_all_runner_platforms_have_pins(self):
        for system, machine, expected in [
            ('Linux', 'x86_64', 'x86_64-unknown-linux-musl'),
            ('Linux', 'aarch64', 'aarch64-unknown-linux-musl'),
            ('Darwin', 'arm64', 'aarch64-apple-darwin'),
            ('Darwin', 'x86_64', 'x86_64-apple-darwin'),
            ('Windows', 'AMD64', 'x86_64-pc-windows-msvc'),
        ]:
            self.assertEqual(bootstrap.runner_target(system, machine), expected)
        with self.assertRaises((KeyError, ValueError)):
            bootstrap.runner_target('Windows', 'arm64')

    def test_incorrect_expected_hash_fails_before_archive_processing(self):
        for target in bootstrap.SHA256:
            with patch.dict(bootstrap.SHA256, {target: '0' * 64}):
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    bootstrap.verified_binary(b'untrusted executable bytes', target)

    def test_verified_archive_layouts(self):
        for target in bootstrap.SHA256:
            stream = io.BytesIO()
            executable = b'fixture executable'
            if target.endswith('windows-msvc'):
                with zipfile.ZipFile(stream, 'w') as archive:
                    archive.writestr('dist.exe', executable)
            else:
                with tarfile.open(fileobj=stream, mode='w:xz') as archive:
                    member = tarfile.TarInfo(f'cargo-dist-{target}/dist')
                    member.size = len(executable)
                    archive.addfile(member, io.BytesIO(executable))
            data = stream.getvalue()
            with patch.dict(bootstrap.SHA256, {target: hashlib.sha256(data).hexdigest()}):
                self.assertEqual(bootstrap.verified_binary(data, target), executable)
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                bootstrap.verified_binary(data, target)

    def test_workflow_trust_boundary(self):
        text = Path('.github/workflows/release.yml').read_text()
        for forbidden in ('cargo-dist-installer', 'matrix.install_dist', 'cargo-dist-cache', 'Install cached dist'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count('run: python3 scripts/dist-bootstrap.py'), 4)
        self.assertEqual(text.count('contents: write'), 1)
        self.assertIn('permissions:\n  contents: read\n', text)
        host = text.split('\n  host:\n')[1]
        self.assertTrue(host.startswith('    permissions:\n      contents: write\n'))
        self.assertLess(host.index('run: python3 scripts/dist-bootstrap.py'), host.index('"$RUNNER_TEMP/wayfinder-dist/dist" host'))
        self.assertNotIn('\n          dist ', host)
        self.assertEqual(text.split('\non:\n')[1].split('\njobs:')[0].strip(), "push:\n    tags:\n      - 'v[0-9]+.[0-9]+.[0-9]+'")


if __name__ == '__main__':
    unittest.main()
