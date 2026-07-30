#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="/usr/local/bin/muonfp"
CONFIG_PATH="/etc/muonfp.conf"
SERVICE_PATH="/etc/systemd/system/muonfp.service"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run this installer as root." >&2
    exit 1
fi

uninstall_muonfp() {
    local purge="${1:-}"

    systemctl disable --now muonfp.service 2>/dev/null || true
    rm -f -- "${SERVICE_PATH}" "${BINARY_PATH}"
    systemctl daemon-reload

    if [[ "${purge}" == "--purge" ]]; then
        rm -f -- "${CONFIG_PATH}"
        rm -rf -- /var/log/pcaps /var/log/fingerprints
        echo "MuonFP, its configuration, and its log data were removed."
    else
        echo "MuonFP was removed. Configuration and log data were preserved."
        echo "Use '$0 --uninstall --purge' to remove those files as well."
    fi
}

case "${1:-}" in
    -uninstall|--uninstall)
        uninstall_muonfp "${2:-}"
        exit 0
        ;;
    --help|-h)
        echo "Usage: sudo ./install.sh [--uninstall [--purge]]"
        exit 0
        ;;
    "")
        ;;
    *)
        echo "Unknown installer option: $1" >&2
        exit 2
        ;;
esac

for required_file in muonfp muonfp.conf muonfp.service; do
    if [[ ! -f "${SCRIPT_DIR}/${required_file}" ]]; then
        echo "Missing release file: ${required_file}" >&2
        exit 1
    fi
done

install -Dm755 "${SCRIPT_DIR}/muonfp" "${BINARY_PATH}"
install -Dm644 "${SCRIPT_DIR}/muonfp.service" "${SERVICE_PATH}"

if [[ ! -e "${CONFIG_PATH}" ]]; then
    install -Dm644 "${SCRIPT_DIR}/muonfp.conf" "${CONFIG_PATH}"
else
    echo "Preserving existing ${CONFIG_PATH}."
fi

install -d -m755 /var/log/pcaps /var/log/fingerprints

systemctl daemon-reload
systemctl enable --now muonfp.service

echo "MuonFP $(muonfp --version) was installed successfully."
echo "Configuration: ${CONFIG_PATH}"
systemctl --no-pager --full status muonfp.service
