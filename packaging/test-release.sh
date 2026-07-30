#!/usr/bin/env bash

set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(dpkg --print-architecture)"
BINARY="dist/muonfp-v${VERSION}-debian12-${ARCH}"
DEB="dist/muonfp_${VERSION}-1_${ARCH}.deb"
TARBALL="dist/muonfp-v${VERSION}-debian12-${ARCH}.tar.gz"

pushd dist >/dev/null
sha256sum --check SHA256SUMS
popd >/dev/null
test -x "${BINARY}"
test "$("${BINARY}" --version)" = "MuonFP v${VERSION}"
test "$("${BINARY}" -version)" = "MuonFP v${VERSION}"
"${BINARY}" --help | grep --fixed-strings -- "--list-interfaces"

dpkg-deb --info "${DEB}"
dpkg-deb --contents "${DEB}" | grep --fixed-strings "./usr/bin/muonfp"
dpkg-deb --contents "${DEB}" | grep --fixed-strings "./etc/muonfp.conf"
dpkg-deb --contents "${DEB}" | grep --fixed-strings "./lib/systemd/system/muonfp.service"

tar -tzf "${TARBALL}" | grep --fixed-strings "install.sh"
INSTALL_MODE="$(tar -tvzf "${TARBALL}" | awk '$NF ~ /install.sh$/ {print $1}')"
test "${INSTALL_MODE}" = "-rwxr-xr-x"

echo "Release artifacts passed structural validation."
