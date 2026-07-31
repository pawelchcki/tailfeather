#!/usr/bin/env bash
#
# Run the whole compatibility measurement: bring up the reference
# implementations, capture ground truth from them, and print the matrix.
#
#   scripts/conformance.sh              # use existing vectors, skip re-capture
#   scripts/conformance.sh --capture    # refresh the lab and the vectors first
#
# Re-capturing needs root, for tcpdump and for tailscaled. The matrix itself
# does not, and runs against committed vectors when no lab is up.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPTURE=0
[[ "${1:-}" == "--capture" ]] && CAPTURE=1

cd "$REPO_ROOT"

if [[ "$CAPTURE" -eq 1 ]]; then
    echo "== bringing up the reference implementations"
    tests/lab/lab.sh up
    tests/lab/lab.sh reference
    echo
    echo "== capturing ground truth"
    sudo tests/lab/capture.sh
    echo
fi

# The suite drives the harness as a subprocess for the checks that must be
# proven in a binary with no libc and no allocator. Cargo discovers
# `.cargo/config.toml` from the working directory, which is what selects the
# bare target, so this cannot be a workspace member and has to be built here.
echo "== building the no_std harness"
(cd harness && cargo build --release)
echo

echo "== compatibility matrix"
cargo run -q -p ts-conformance --bin conformance
