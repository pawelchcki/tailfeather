#!/usr/bin/env bash
#
# Build and flash the firmware, taking configuration from the gitignored `.env`
# at the repository root.
#
# The firmware reads its SSID, keys and tunnel address through `env!`, and the
# `[env]` block in firmware/.cargo/config.toml holds only placeholders. Cargo
# lets the real environment win over `[env]` entries that are not `force`d, so
# exporting these here is all it takes to override them.
#
#   scripts/flash.sh              # build, flash, then monitor
#   scripts/flash.sh --no-monitor # build and flash only
#
# The user needs access to the serial port. If they are not in the `dialout`
# group this runs espflash under sudo, which avoids a persistent group change
# that would not take effect until the next login anyway.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
MONITOR=1
[[ "${1:-}" == "--no-monitor" ]] && MONITOR=0

if [[ ! -f "$ENV_FILE" ]]; then
    echo "missing $ENV_FILE — copy .env.example and fill it in" >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

for var in WIFI_SSID WIFI_PASSWORD WG_PRIVATE_KEY WG_PEER_PUBLIC_KEY WG_TUNNEL_IP; do
    if [[ -z "${!var:-}" ]]; then
        echo "$var is not set in $ENV_FILE" >&2
        exit 1
    fi
done

echo "== building for SSID '$WIFI_SSID', tunnel address $WG_TUNNEL_IP"
cd "$REPO_ROOT/firmware"
cargo build --release

BINARY="$REPO_ROOT/firmware/target/riscv32imac-unknown-none-elf/release/esp-gateway-firmware"

# Resolved to an absolute path because espflash usually lives in ~/.cargo/bin,
# which is not on root's PATH when this re-invokes itself under sudo.
ESPFLASH="$(command -v espflash || true)"
if [[ -z "$ESPFLASH" ]]; then
    echo "espflash not found; install it with 'cargo install espflash'" >&2
    exit 1
fi

FLASH=("$ESPFLASH" flash --chip esp32c6)
[[ "$MONITOR" -eq 1 ]] && FLASH+=(--monitor)
FLASH+=("$BINARY")

if id -nG | tr ' ' '\n' | grep -qx dialout; then
    "${FLASH[@]}"
else
    echo "== not in the 'dialout' group, flashing via sudo"
    sudo -E "${FLASH[@]}"
fi
