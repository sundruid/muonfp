![MuonFP logo](https://github.com/user-attachments/assets/ec3a4b97-ddd0-4b12-b6bd-d02954d46c64)

# MuonFP

MuonFP is an open-source passive TCP fingerprint sensor. It observes TCP SYN
and SYN-ACK packets and records a compact signature derived from the TCP window
size, option order, MSS, and window scale.

MuonFP is useful for network-security research, reconnaissance detection, and
feeding fingerprint-aware tools such as
[Fingerprint Firewall](https://github.com/sundruid/fpfw).

Read the background paper:
[There is No Such Thing as a “Benign” Internet Scanner](https://www.kenwebster.com/index.php/2025/01/29/there-is-no-such-thing-as-a-benign-internet-scanner/).

## Features

- IPv4 and IPv6 TCP SYN/SYN-ACK fingerprinting.
- IPv6 extension-header traversal for common option and fragment headers.
- JSON Lines fingerprint output with UTC timestamps and sensor hostname.
- Rotating fingerprint and PCAP output with restart-safe active logs.
- Optional immediate JSON output through `--stdout`.
- Automatic Linux interface selection or an explicit configured interface.
- `/dev/null` support when PCAP recording is not wanted.
- systemd service and Debian release artifacts.

MuonFP records fingerprints; policy matching and traffic blocking are performed
by downstream tools such as Fingerprint Firewall.

## Fingerprint format

Example:

```text
26847:2-4-8-1-3:1460:8
```

The four fields are:

1. TCP window size.
2. TCP option Kind values in their exact on-wire order.
3. TCP Maximum Segment Size.
4. TCP window scale.

See [MuonFP Fingerprint Specification](MuonFP%20Fingerprint%20Specification.md)
for the draft format specification.

## Command line

```text
MuonFP - open-source TCP fingerprinting

Usage: muonfp [OPTIONS]

Options:
  -v, --version, -version  Show version information
  -s, --stdout             Output JSON fingerprints to stdout immediately
      --list-interfaces     List available capture interfaces
  -h, --help               Show this help message
```

All version forms report the Cargo package version:

```console
$ muonfp --version
MuonFP v1.5.0
```

## Debian installation

MuonFP 1.5.0 Linux artifacts are built on Debian 12 amd64 and support Debian 12
and Debian 13 amd64.

### Debian package

```bash
curl -LO https://github.com/sundruid/muonfp/releases/download/v1.5.0/muonfp_1.5.0-1_amd64.deb
sudo apt install ./muonfp_1.5.0-1_amd64.deb
```

### Compatibility installer

```bash
curl -LO https://github.com/sundruid/muonfp/releases/download/v1.5.0/muonfp-v1.5.0-debian12-amd64.tar.gz
tar -xzf muonfp-v1.5.0-debian12-amd64.tar.gz
cd muonfp-v1.5.0
sudo ./install.sh
```

The installer preserves an existing `/etc/muonfp.conf`. Uninstalling also
preserves configuration and logs by default:

```bash
sudo ./install.sh --uninstall
```

Use `--uninstall --purge` only when configuration and collected log data should
also be deleted.

### Binary-only upgrade

Existing manual installations can replace only the executable:

```bash
curl -LO https://github.com/sundruid/muonfp/releases/download/v1.5.0/muonfp-v1.5.0-debian12-amd64
sudo systemctl stop muonfp
sudo cp /usr/local/bin/muonfp /usr/local/bin/muonfp.previous
sudo install -m755 muonfp-v1.5.0-debian12-amd64 /usr/local/bin/muonfp
/usr/local/bin/muonfp --version
sudo systemctl start muonfp
```

Verify downloads against `SHA256SUMS` from the release before installation.

## Configuration

The service reads `/etc/muonfp.conf`:

```ini
interface=auto
fingerprints=/var/log/fingerprints
pcap=/var/log/pcaps
max_file_size=10
```

- `interface=auto` selects the Linux default-route interface. Use
  `muonfp --list-interfaces` and set a name explicitly when needed.
- Set `pcap=/dev/null` to disable PCAP recording.
- `max_file_size` is the rotation threshold in MiB and must be greater than
  zero.

Packet capture requires root or `CAP_NET_RAW`.

## Build from source

MuonFP requires Rust 1.85 or newer:

```bash
git clone https://github.com/sundruid/muonfp.git
cd muonfp
cargo build --release --locked
./target/release/muonfp --version
```

Before submitting a change:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
```

## License

MuonFP source code is released under the [MIT License](LICENSE). The fingerprint
format specification carries its own CC BY 4.0 notice.

Contact: sundruid@protonmail.com
