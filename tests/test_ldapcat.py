"""Tests use synthetic LDIF and TLS data, never the live directory."""
import hashlib
import io
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'ldapcat'
loader = importlib.machinery.SourceFileLoader('ldapcat', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
ldapcat = importlib.util.module_from_spec(spec)
loader.exec_module(ldapcat)


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.tls = {
            '/certs/server.crt': b'synthetic certificate\n',
            '/certs/server.key': bytes(range(256)) * 600,
        }

    def docker(self, args, stdout, stderr, timeout):
        self.calls.append(args)
        self.assertEqual(args[:3], ['docker', 'exec', 'test-ldap'])
        if args[3] == 'slapcat':
            stdout.write(b'dn: cn=test\ncn: test\n\n')
        else:
            self.assertEqual(args[3:5], ['cat', '--'])
            stdout.write(self.tls[args[5]])
        return subprocess.CompletedProcess(args, 0)

    def test_invalid_tls_paths_fail_before_export(self):
        for source in ['relative.pem', '-option', '/', '/certs/', '/certs/../key', '/a\x00b', '/a\nb']:
            with self.subTest(source=source), \
                    patch.object(ldapcat.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'absolute.*file path'):
                    ldapcat.backup(self.root / 'not-created', 'test-ldap', [source])
                run.assert_not_called()
                self.assertFalse((self.root / 'not-created').exists())

    def test_default_backup_preserves_format_one(self):
        with patch.object(ldapcat.subprocess, 'run', side_effect=self.docker):
            result = ldapcat.backup(self.root, 'test-ldap')
        manifest = json.loads((result / 'manifest.json').read_text())
        self.assertEqual(manifest['format'], 1)
        self.assertNotIn('tls_files', manifest)
        self.assertEqual(set(manifest['files']), {'config.ldif', 'data.ldif'})
        self.assertFalse((result / 'tls').exists())
        self.assertEqual(len(self.calls), 2)

    def test_same_basename_and_shell_characters_are_safe(self):
        self.tls = {'/first/server.pem': b'first', '/other/server.pem': b'second',
                    '/certs/$(touch stolen); key.pem': b'third'}
        with patch.object(ldapcat.subprocess, 'run', side_effect=self.docker):
            result = ldapcat.backup(self.root, 'test-ldap', list(self.tls))
        manifest = json.loads((result / 'manifest.json').read_text())
        self.assertEqual(len(manifest['tls_files']), 3)
        for name, source in manifest['tls_files'].items():
            self.assertEqual((result / name).read_bytes(), self.tls[source])

    def test_tls_failures_remove_entire_staging_directory(self):
        for failure in ['nonzero', 'empty', 'timeout', 'interrupt']:
            with self.subTest(failure=failure):
                def fail(args, stdout, stderr, timeout):
                    if args[3] == 'slapcat' or args[-1].endswith('.crt'):
                        return self.docker(args, stdout, stderr, timeout)
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(args, timeout)
                    if failure == 'interrupt':
                        raise KeyboardInterrupt()
                    if failure == 'nonzero':
                        stdout.write(b'partial secret')
                        return subprocess.CompletedProcess(args, 1, stderr=b'secret diagnostic')
                    return subprocess.CompletedProcess(args, 0)
                with patch.object(ldapcat.subprocess, 'run', side_effect=fail):
                    with self.assertRaises((RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt)) as caught:
                        ldapcat.backup(self.root, 'test-ldap', list(self.tls))
                self.assertNotIn('secret', str(caught.exception))
                self.assertEqual(list(self.root.iterdir()), [])

    def test_cli_exposes_repeatable_tls_file_option(self):
        with patch.object(ldapcat.sys, 'argv', [str(SCRIPT), str(self.root),
                         '--container', 'test-ldap', '--tls-file', '/certs/server.crt',
                         '--tls-file', '/certs/server.key']), \
                patch.object(ldapcat.subprocess, 'run', side_effect=self.docker):
            self.assertEqual(ldapcat.main(), 0)
        result, = self.root.iterdir()
        manifest = json.loads((result / 'manifest.json').read_text())
        self.assertEqual(set(manifest['tls_files'].values()), set(self.tls))

    def test_cli_failure_is_sanitized_and_cleans_up(self):
        def fail(args, stdout, stderr, timeout):
            if args[3] == 'slapcat':
                return self.docker(args, stdout, stderr, timeout)
            stdout.write(b'partial private key')
            return subprocess.CompletedProcess(args, 1, stderr=b'secret diagnostic')
        errors = io.StringIO()
        with patch.object(ldapcat.sys, 'argv', [str(SCRIPT), str(self.root),
                         '--container', 'test-ldap', '--tls-file', '/certs/server.key']), \
                patch.object(ldapcat.sys, 'stderr', errors), \
                patch.object(ldapcat.subprocess, 'run', side_effect=fail):
            self.assertEqual(ldapcat.main(), 1)
        self.assertIn('TLS file export failed', errors.getvalue())
        self.assertNotIn('secret', errors.getvalue())
        self.assertNotIn('private key', errors.getvalue())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_tls_files_are_private_and_manifest_tracks_sources(self):
        with patch.object(ldapcat.subprocess, 'run', side_effect=self.docker):
            result = ldapcat.backup(self.root, 'test-ldap', tls_files=list(self.tls))
        manifest = json.loads((result / 'manifest.json').read_text())
        self.assertEqual(manifest['format'], 2)
        self.assertEqual(set(manifest['tls_files'].values()), set(self.tls))
        for relative, source in manifest['tls_files'].items():
            target = result / relative
            self.assertEqual(target.read_bytes(), self.tls[source])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(manifest['files'][relative], {
                'bytes': len(self.tls[source]),
                'sha256': hashlib.sha256(self.tls[source]).hexdigest(),
            })
        self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((result / 'tls').stat().st_mode), 0o700)


if __name__ == '__main__':
    unittest.main()
