# ldapcat

ldapcat is a lightweight command-line backup wrapper for your Docker-hosted OpenLDAP service. Inspired by Zimbra’s zmslapcat, it exports the entire directory and its configuration with a single command:

```sh
python3 ldapcat /opt/backup/
```

It saves users, groups, attributes, schemas, ACLs, and overlays into a private, timestamped backup folder, along with a manifest containing entry counts and SHA-256 checksums.
It runs without stopping LDAP, avoids overwriting previous backups, and removes incomplete exports when an error occurs.

Requires Python 3, Docker access, and `slapcat` in the running container. The default container is `openldap-webapp-ldap`; use `--container NAME` or `LDAPCAT_CONTAINER` to override it. Database 0 is configuration and database 1 is directory data; additional databases are not exported.

## Include TLS certificates and private keys

TLS files are opt-in because they can contain private keys. Repeat `--tls-file` for each absolute **container-side** path, including your server certificate, private key, CA bundle, and any other files required by your TLS configuration:

```sh
python3 ldapcat /opt/backup/ --container openldap-webapp-ldap \
  --tls-file /container/service/slapd/assets/certs/ldap.crt \
  --tls-file /container/service/slapd/assets/certs/ldap.key \
  --tls-file /container/service/slapd/assets/certs/ca.crt
```

These are example paths: use the paths referenced by your configuration (for example `olcTLSCertificateFile`, `olcTLSCertificateKeyFile`, and `olcTLSCACertificateFile`). There is no automatic discovery or recursive directory copy. The container must have `cat` available and its default exec user must be able to read the selected files. Container-side symlinks are followed, so mounted or rotated certificate links are backed up as file contents, not symlinks. Missing, unreadable, or empty files fail the entire backup and remove its staging directory. Paths with parent traversal or control characters are rejected.

Selected files are copied byte-for-byte to `tls/0001.pem`, `tls/0002.pem`, etc. Generated names avoid collisions when different paths share a basename; the `.pem` suffix does not convert or validate the content. The format-2 manifest adds a `tls_files` mapping from backup-relative filename to original container path. Its `files` entries contain byte counts and SHA-256 checksums (LDIF entries also have entry counts). Without `--tls-file`, the existing format-1 manifest and LDAP-only behavior are retained.

Backups contain password hashes and, when selected, TLS private keys. The backup subfolder and TLS subfolder have mode `0700`; files have mode `0600`. Backups are **not encrypted at rest**. Protect the backup destination and any off-host copies. TLS material is streamed through `docker exec`, not through LDAP; this option does not add remote LDAPS/StartTLS export or change the running server's TLS settings.

Exports are sequential, not an atomic snapshot. Avoid directory/configuration writes and certificate rotation for the duration of a backup. Only explicitly selected TLS files are included; Compose files, the web application, and other external dependencies remain outside the backup.

## Restoring TLS files

There is no automatic restore command. Verify each file's checksum against `manifest.json`, then use `tls_files` to identify its original container path. Restore files into the appropriate persistent host mounts or Docker volumes before starting the restored LDAP service, preserving the ownership and permissions required by that service (particularly for private keys). Backup modes protect the archive; they do not record original ownership or modes. Do not blindly copy manifest paths to your host filesystem. Restore `config.ldif` and `data.ldif` using your OpenLDAP recovery procedure, and verify the certificate/key pair, trust chain, and hostname before use.

## Tests

The unit suite uses synthetic data and does not touch a running directory:

```sh
python3 -m unittest discover -s tests -v
```

To also run the real Docker integration test, make `osixia/openldap:1.5.0` available locally and run:

```sh
docker pull osixia/openldap:1.5.0
LDAPCAT_DOCKER_TESTS=1 python3 -m unittest discover -s tests -v
```

The integration test creates a disposable OpenLDAP container with generated test certificates, no network access, no published ports, and no host mounts. It verifies LDIF exports, certificate/key bytes and checksums, symlink handling, private permissions, and failed-copy cleanup. It removes the test container and its anonymous volumes afterward. It never reads the live LDAP service. Set `LDAPCAT_TEST_IMAGE` to test a compatible alternative image.
