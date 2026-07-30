#!/usr/bin/env bash

set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Release artifacts must be built on Linux." >&2
    exit 1
fi

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(dpkg --print-architecture)"
PLATFORM="debian12-${ARCH}"
DIST_DIR="${REPO_ROOT}/dist"
STAGING_ROOT="$(mktemp -d)"
trap 'rm -rf -- "${STAGING_ROOT}"' EXIT

if [[ -z "${VERSION}" ]]; then
    echo "Unable to determine package version." >&2
    exit 1
fi
if [[ "${ARCH}" != "amd64" ]]; then
    echo "This release workflow currently supports Debian amd64 only." >&2
    exit 1
fi

cargo build --release --locked
strip target/release/muonfp

rm -rf -- "${DIST_DIR}"
install -d -m755 "${DIST_DIR}"

BINARY_ASSET="muonfp-v${VERSION}-${PLATFORM}"
install -m755 target/release/muonfp "${DIST_DIR}/${BINARY_ASSET}"

DEB_ROOT="${STAGING_ROOT}/deb"
install -d -m755 \
    "${DEB_ROOT}/DEBIAN" \
    "${DEB_ROOT}/etc" \
    "${DEB_ROOT}/lib/systemd/system" \
    "${DEB_ROOT}/usr/bin" \
    "${DEB_ROOT}/usr/share/doc/muonfp"
install -m755 target/release/muonfp "${DEB_ROOT}/usr/bin/muonfp"
install -m644 muonfp.conf "${DEB_ROOT}/etc/muonfp.conf"
install -m644 packaging/muonfp.service "${DEB_ROOT}/lib/systemd/system/muonfp.service"
install -m644 packaging/copyright "${DEB_ROOT}/usr/share/doc/muonfp/copyright"
gzip -9cn CHANGELOG.md > "${DEB_ROOT}/usr/share/doc/muonfp/changelog.gz"

sed \
    -e "s/@VERSION@/${VERSION}/g" \
    -e "s/@ARCH@/${ARCH}/g" \
    packaging/debian/control > "${DEB_ROOT}/DEBIAN/control"
install -m644 packaging/debian/conffiles "${DEB_ROOT}/DEBIAN/conffiles"
install -m755 packaging/debian/postinst "${DEB_ROOT}/DEBIAN/postinst"
install -m755 packaging/debian/prerm "${DEB_ROOT}/DEBIAN/prerm"
install -m755 packaging/debian/postrm "${DEB_ROOT}/DEBIAN/postrm"

DEB_ASSET="muonfp_${VERSION}-1_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${DEB_ROOT}" "${DIST_DIR}/${DEB_ASSET}"

BUNDLE_ROOT="${STAGING_ROOT}/muonfp-v${VERSION}"
install -d -m755 "${BUNDLE_ROOT}"
install -m755 target/release/muonfp "${BUNDLE_ROOT}/muonfp"
install -m755 install.sh "${BUNDLE_ROOT}/install.sh"
install -m644 muonfp.service "${BUNDLE_ROOT}/muonfp.service"
install -m644 muonfp.conf "${BUNDLE_ROOT}/muonfp.conf"
install -m644 LICENSE CHANGELOG.md README.md RELEASE_NOTES.md \
    "MuonFP Fingerprint Specification.md" "${BUNDLE_ROOT}/"

TARBALL_ASSET="muonfp-v${VERSION}-${PLATFORM}.tar.gz"
tar --create --gzip --file "${DIST_DIR}/${TARBALL_ASSET}" \
    --directory "${STAGING_ROOT}" "muonfp-v${VERSION}"

(
    cd "${DIST_DIR}"
    sha256sum "${BINARY_ASSET}" "${DEB_ASSET}" "${TARBALL_ASSET}" > SHA256SUMS
)

printf 'Built release artifacts in %s\n' "${DIST_DIR}"
ls -lh "${DIST_DIR}"
