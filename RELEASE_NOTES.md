# MuonFP 1.5.0

MuonFP 1.5.0 promotes the RC.5 feature set to a tested production release.
It adds IPv6 TCP fingerprinting, immediate JSONL output on stdout, a consistent
version command, safer log rotation, automatic interface selection, updated
dependencies, and reproducible Debian release artifacts.

## Downloads

- `muonfp_1.5.0-1_amd64.deb` — Debian package for Debian 12 or newer on amd64.
- `muonfp-v1.5.0-debian12-amd64.tar.gz` — binary, configuration, systemd unit,
  and compatibility installer.
- `muonfp-v1.5.0-debian12-amd64` — standalone executable for upgrading an
  existing installation.
- `SHA256SUMS` — SHA-256 digests for all three artifacts.

The Linux executable is built in Debian 12 and is intended for Debian 12 and
Debian 13 amd64 systems.

## Existing-install upgrade

To replace only the executable:

```bash
sudo systemctl stop muonfp
sudo install -m755 muonfp-v1.5.0-debian12-amd64 /usr/local/bin/muonfp
/usr/local/bin/muonfp --version
sudo systemctl start muonfp
```

Back up the previous executable before replacement. Existing configuration and
logs are compatible and should be preserved.

## Highlights

- IPv4 and IPv6 SYN/SYN-ACK fingerprinting.
- IPv6 Hop-by-Hop, Routing, Fragment, Authentication, and Destination Options
  header traversal.
- `-v`, `--version`, and the legacy `-version` spelling all report
  `MuonFP v1.5.0`.
- `-s`/`--stdout` emits each JSON fingerprint immediately.
- `--list-interfaces` lists available capture interfaces.
- `interface=auto` selects the Linux default-route interface.
- Malformed TCP and extension headers are ignored safely.
- Active output is preserved across service restarts.

See `CHANGELOG.md` and `docs/releases/v1.5.0-rollback.md` for the complete
change and recovery records.
