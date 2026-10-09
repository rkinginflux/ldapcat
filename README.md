# ldapcat

ldapcat is a lightweight command-line backup wrapper for your Docker-hosted OpenLDAP service. Inspired by Zimbra’s zmslapcat, it exports the entire directory and its configuration with a single command:
```
ldapcat /opt/backup/
```
It saves users, groups, attributes, schemas, ACLs, and overlays into a private, timestamped backup folder, along with a manifest containing entry counts and SHA-256 checksums.
It runs without stopping LDAP, avoids overwriting previous backups, and removes incomplete exports when an error occurs.
In short: “A one-command LDAP export utility that makes complete directory and configuration backups simple.”
