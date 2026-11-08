# RestoreGate — English overview

**RestoreGate** is an offline, dependency-free Python CLI that inspects ZIP/TAR backup archives for structural and recovery risks. Unlike a backup scheduler, RestoreGate provides an independent **recoverability gate**: bounded stream reads, dangerous-path rejection, duplicate and case-collision detection, and an optional isolated restore/readback drill.

**Status:** v0.1.0; remote CI and releases are not claimed until actually run and published.

## Core CLI

```bash
python -m pip install .
restoregate scan path/to/backup.zip
restoregate drill path/to/backup.tar.gz --json-out evidence.json --sarif-out evidence.sarif
restoregate drill backup.zip --policy examples/policy.json
```

`scan` streams and checks member payloads without extraction. `drill` additionally writes to a private ephemeral directory, rereads every restored file and compares SHA-256, then deletes the temporary directory. No archive contents are executed or written to a user-selected restore directory.

Supports ZIP, TAR, TAR.GZ, TAR.BZ2 and TAR.XZ. Policies cover archive size, per-file size, total expanded size, ZIP per-member compression ratio, maximum depth/count, source filesystem mtime age, required paths and minimum file count. Exit codes: `0` pass, `1` archive failure, `2` policy/evidence-output error.

Security boundaries: no malware scan, encrypted archive support, database transactional validation, encryption, cryptographic attestation, RTO/RPO test, or protection against a hostile source host. Some metadata fields (such as `mtime`) are not authenticated; isolation and resource quotas should be supplied externally for untrusted archives.

Tests: `python -m unittest discover -s tests -v`. GitHub Actions is configured to test Python 3.10–3.13 on Linux, Windows and macOS, but its actual result must be verified after publishing.

For complete implementation detail, constraints, policy keys, architecture, references and contribution instructions, consult the [Portuguese README](README.md), [threat model](docs/THREAT_MODEL.md), [security policy](SECURITY.md) and [license](LICENSE).

**Author:** Felipe Silva ([@felipewatter](https://github.com/felipewatter)) · MIT.
