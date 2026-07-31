#!/usr/bin/env bash
#
# Measure throughput through the gateway acting as an exit node, and confirm
# that traffic really leaves via the device's own WiFi address.
#
#     client (netns) --wireguard--> ESP32 --NAT--> echo server (this host)
#
# The client has to live in a network namespace. The echo server is reachable
# at this machine's LAN address, and a host cannot route traffic to its own
# address through a tunnel — it would go straight to loopback and never touch
# the device. A namespace has no such shortcut, so its packets take the tunnel.
#
# The namespace still needs to reach the device's LAN address to carry the
# WireGuard packets themselves, which is what the explicit /32 route and the
# host masquerade rule are for. Without that /32 the encrypted packets would
# match the tunnel's own 0.0.0.0/0 AllowedIPs and loop.
#
# The echo server reports the source address it observes. That address is the
# proof of source NAT: it must be the device's address, not the client's.
#
#   sudo scripts/bench-exit.sh <device lan ip> [seconds] [payload bytes]

set -euo pipefail

NS=wgbench
VETH_HOST=vbh0
VETH_NS=vbn0
UNDERLAY_HOST=10.96.0.1
UNDERLAY_NS=10.96.0.2
TUNNEL_CLIENT=10.99.0.1
TUNNEL_DEVICE=10.99.0.2
DEVICE_PORT=51820
SERVER_PORT=9999

DEVICE_IP="${1:-}"
DURATION="${2:-20}"
PAYLOAD="${3:-1024}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
WORK="$(mktemp -d)"
SERVER_PID=""

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0 $*" >&2
    exit 1
fi
if [[ -z "$DEVICE_IP" ]]; then
    echo "usage: $0 <device lan ip> [seconds] [payload bytes]" >&2
    exit 2
fi

FORWARD_WAS=""

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$UNDERLAY_NS/32" -j MASQUERADE 2>/dev/null || true
    # Leave the machine's forwarding setting as it was found; a benchmark has
    # no business permanently turning the developer's laptop into a router.
    [[ -n "$FORWARD_WAS" ]] && sysctl -qw net.ipv4.ip_forward="$FORWARD_WAS"
    rm -rf "$WORK"
}
trap cleanup EXIT

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

SERVER_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
UPLINK="$(ip -4 -o route get "$DEVICE_IP" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
echo "== echo server will listen on $SERVER_IP:$SERVER_PORT (uplink $UPLINK)"

echo "== namespace and underlay"
ip netns delete "$NS" 2>/dev/null || true
ip link del "$VETH_HOST" 2>/dev/null || true
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"
ip addr add "$UNDERLAY_HOST/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip -n "$NS" addr add "$UNDERLAY_NS/24" dev "$VETH_NS"
ip -n "$NS" link set "$VETH_NS" up
ip -n "$NS" link set lo up
ip -n "$NS" route add default via "$UNDERLAY_HOST"

FORWARD_WAS="$(sysctl -n net.ipv4.ip_forward)"
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s "$UNDERLAY_NS/32" -j MASQUERADE 2>/dev/null ||
    iptables -t nat -A POSTROUTING -s "$UNDERLAY_NS/32" -j MASQUERADE

echo "== wireguard client inside the namespace"
umask 077
printf '%s\n' "$LAPTOP_PRIVATE_KEY_B64" >"$WORK/lap.key"
ip -n "$NS" link add wg0 type wireguard
ip -n "$NS" addr add "$TUNNEL_CLIENT/24" dev wg0
ip netns exec "$NS" wg set wg0 \
    private-key "$WORK/lap.key" \
    peer "$DEVICE_PUBLIC_KEY_B64" \
    endpoint "$DEVICE_IP:$DEVICE_PORT" \
    allowed-ips 0.0.0.0/0
ip -n "$NS" link set wg0 up
# The encrypted packets must reach the device directly, not via the tunnel they
# are carrying.
ip -n "$NS" route add "$DEVICE_IP/32" via "$UNDERLAY_HOST" dev "$VETH_NS"
# Only the server is routed through the tunnel, which keeps the rest of the
# namespace's traffic (and this script's own control paths) out of the way.
ip -n "$NS" route add "$SERVER_IP/32" dev wg0

echo "== warming up the tunnel"
ip netns exec "$NS" ping -c 3 -W 3 "$TUNNEL_DEVICE" >/dev/null 2>&1 || true

echo "== starting echo server"
python3 "$REPO_ROOT/scripts/bench_echo_server.py" "$SERVER_PORT" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

echo "== benchmarking for ${DURATION}s with ${PAYLOAD}-byte payloads"
ip netns exec "$NS" python3 "$REPO_ROOT/scripts/bench_client.py" \
    "$SERVER_IP" "$SERVER_PORT" "$DURATION" "$PAYLOAD" "${4:-}"

echo
echo "== echo server report"
kill -INT "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
cat "$WORK/server.log"

echo
echo "== device peer state"
ip netns exec "$NS" wg show wg0 | grep -E "handshake|transfer"
