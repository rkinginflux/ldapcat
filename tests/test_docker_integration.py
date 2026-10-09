"""Opt-in real OpenLDAP test: LDAPCAT_DOCKER_TESTS=1 python3 -m unittest discover -s tests -v."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / 'ldapcat'


@unittest.skipUnless(os.environ.get('LDAPCAT_DOCKER_TESTS') == '1',
                     'set LDAPCAT_DOCKER_TESTS=1 for isolated Docker integration')
class DockerIntegrationTests(unittest.TestCase):
    def test_real_slapcat_and_tls_backup(self):
        # No host ports, host mounts, or access to the user's directory service.
        name = 'ldapcat-test-' + uuid.uuid4().hex
        image = os.environ.get('LDAPCAT_TEST_IMAGE', 'osixia/openldap:1.5.0')
        subprocess.run(['docker', 'image', 'inspect', image], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        try:
            subprocess.run(['docker', 'run', '-d', '--name', name,
                            '--network', 'none', '--hostname', 'ldapcat.example.test',
                            '--add-host', 'ldapcat.example.test:127.0.0.1',
                            '--memory', '512m', '--cpus', '1',
                            '-e', 'LDAP_DOMAIN=example.test', image],
                           check=True, stdout=subprocess.DEVNULL, timeout=60)
            for _ in range(60):
                ready = subprocess.run(
                    ['docker', 'exec', name, 'ldapsearch', '-x', '-H',
                     'ldap://127.0.0.1', '-b', '', '-s', 'base', '(objectClass=*)'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                self.fail('Disposable LDAP container did not become ready')
            prefix = '/container/service/slapd/assets/certs/'
            sources = [prefix + leaf for leaf in ['ldap.crt', 'ldap.key', 'ca.crt']]
            # Verify real container symlinks are copied as bytes, not host links.
            subprocess.run(['docker', 'exec', name, 'ln', '-s', sources[0],
                            '/tls-certificate-link'], check=True, timeout=10)
            sources.append('/tls-certificate-link')
            with tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / 'backups'
                command = [sys.executable, str(SCRIPT), str(destination), '--container', name]
                for source in sources:
                    command.extend(['--tls-file', source])
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                backup, = destination.iterdir()
                manifest = json.loads((backup / 'manifest.json').read_text())
                self.assertEqual(set(manifest['tls_files'].values()), set(sources))
                for relative, source in manifest['tls_files'].items():
                    expected = subprocess.run(['docker', 'exec', name, 'cat', '--', source],
                                              check=True, capture_output=True, timeout=10).stdout
                    target = backup / relative
                    # Compare digests rather than printing secret bytes on failure.
                    digest = hashlib.sha256(expected).hexdigest()
                    self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
                    self.assertEqual(manifest['files'][relative]['sha256'], digest)
                    self.assertFalse(target.is_symlink())
                for target in backup.rglob('*'):
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode),
                                     0o700 if target.is_dir() else 0o600)
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
                for ldif in ['config.ldif', 'data.ldif']:
                    self.assertGreater(manifest['files'][ldif]['entries'], 0)
                failed = subprocess.run(command + ['--tls-file', '/missing.key'],
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(failed.returncode, 1)
                self.assertNotIn('Traceback', failed.stderr)
                self.assertEqual(list(destination.iterdir()), [backup])
        finally:
            subprocess.run(['docker', 'rm', '-f', '-v', name], check=True,
                           stdout=subprocess.DEVNULL, timeout=30)


if __name__ == '__main__':
    unittest.main()
