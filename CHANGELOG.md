# Changelog

All notable changes to MuonFP are documented here.

## 1.5.0 - 2026-07-30

### Added

- IPv6 TCP fingerprinting, including common IPv6 extension-header chains.
- `--stdout`/`-s`, `--help`/`-h`, `--version`/`-v`/`-version`, and
  `--list-interfaces` command-line options.
- Automatic selection of the default Linux network interface with
  `interface=auto`.
- Automated tests, dependency auditing, Debian packaging, and GitHub release
  workflows.
- A proper Debian package, a compatibility installer bundle, and a standalone
  Debian amd64 executable.

### Changed

- Updated supported Rust dependencies to their latest compatible releases and
  committed `Cargo.lock` for reproducible application builds.
- Unified the package and runtime version as `1.5.0`.
- Active fingerprint and PCAP logs now survive service restarts and rotate
  without overwriting existing files.
- The compatibility installer is repeatable and preserves configuration and
  log data unless an explicit purge is requested.
- Clarified that MuonFP is licensed under the MIT License.

### Fixed

- Rejected malformed TCP header lengths instead of panicking.
- Rejected truncated Ethernet and IPv6 extension headers safely.
- Replaced the macOS-specific default `en0` interface in Debian artifacts.
- Preserved executable permissions in release archives.

## 0.1.4 - 2025-07-02

- Accepted `/dev/null` as the PCAP destination.
- Added uninstall support to the compatibility installer.
