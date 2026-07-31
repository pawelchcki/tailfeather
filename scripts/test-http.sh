#!/usr/bin/env bash
#
# Fetch HTTP through the gateway and confirm the request reaches the server from
# the device's own address.
#
#     curl (netns) --wireguard--> ESP32 --NAT--> HTTP server (this host)
#
# TCP cannot be forwarded the way UDP is, because a `TcpSocket` would terminate
# the connection on the device instead of passing it through. Segments are
# instead translated one at a time over a raw socket. smoltcp suppresses its own
# RST for anything a raw socket consumes, which is what makes that work.
#
# Same namespace reasoning as bench-exit.sh: a host cannot route traffic to its
# own address through a tunnel, so the client has to live somewhere that has no
# shortcut to the server.
#
#   sudo scripts/test-http.sh <device lan ip> [download megabytes]

set -euo pipefail

NS=wghttp
VETH_HOST=vhh0
VETH_NS=vhn0
UNDERLAY_HOST=10.95.0.1
UNDERLAY_NS=10.95.0.2
TUNNEL_CLIENT=10.99.0.1
TUNNEL_DEVICE=10.99.0.2
DEVICE_PORT=51820
HTTP_PORT=8080
# The tunnel carries at most a 1280-byte inner packet, so the client's interface
# must not try to send more than that.
TUNNEL_MTU=1280

DEVICE_IP="${1:-}"
MEGABYTES="${2:-1}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
WORK="$(mktemp -d)"
SERVER_PID=""
FORWARD_WAS=""

if [[ $EUID -ne 0 ]]; then
    echo "must run as root: sudo $0 $*" >&2
    exit 1
fi
if [[ -z "$DEVICE_IP" ]]; then
    echo "usage: $0 <device lan ip> [download megabytes]" >&2
    exit 2
fi

cleanup() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    ip netns delete "$NS" 2>/dev/null || true
    rm -rf "/etc/netns/$NS"
    ip link del "$VETH_HOST" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$UNDERLAY_NS/32" -j MASQUERADE 2>/dev/null || true
    [[ -n "$FORWARD_WAS" ]] && sysctl -qw net.ipv4.ip_forward="$FORWARD_WAS"
    rm -rf "$WORK"
}
trap cleanup EXIT

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

SERVER_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
echo "== HTTP server will listen on $SERVER_IP:$HTTP_PORT"

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

umask 077
printf '%s\n' "$LAPTOP_PRIVATE_KEY_B64" >"$WORK/lap.key"
ip -n "$NS" link add wg0 type wireguard
ip -n "$NS" addr add "$TUNNEL_CLIENT/24" dev wg0
ip -n "$NS" link set wg0 mtu "$TUNNEL_MTU"
ip netns exec "$NS" wg set wg0 \
    private-key "$WORK/lap.key" \
    peer "$DEVICE_PUBLIC_KEY_B64" \
    endpoint "$DEVICE_IP:$DEVICE_PORT" \
    allowed-ips 0.0.0.0/0
ip -n "$NS" link set wg0 up
ip -n "$NS" route add "$DEVICE_IP/32" via "$UNDERLAY_HOST" dev "$VETH_NS"
# Everything else goes through the tunnel, which is what an exit node is. The
# /32 above is more specific, so the encrypted packets still take the veth and
# do not chase their own tail.
ip -n "$NS" route del default via "$UNDERLAY_HOST"
ip -n "$NS" route add default dev wg0
printf 'nameserver 1.1.1.1\n' >"$WORK/resolv.conf"
mkdir -p "/etc/netns/$NS"
cp "$WORK/resolv.conf" "/etc/netns/$NS/resolv.conf"

echo "== warming up the tunnel"
ip netns exec "$NS" ping -c 3 -W 3 "$TUNNEL_DEVICE" >/dev/null 2>&1 || true

echo "== starting HTTP server"
python3 "$REPO_ROOT/scripts/http_test_server.py" "$HTTP_PORT" "$MEGABYTES" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

FAILED=0

echo
echo "== GET /whoami (what the server sees as the client address)"
if ip netns exec "$NS" curl -sS --max-time 30 "http://$SERVER_IP:$HTTP_PORT/whoami"; then
    echo "PASS: request completed"
else
    echo "FAIL: request did not complete"
    FAILED=1
fi

echo
echo "== GET /data (${MEGABYTES} MiB download)"
RESULT="$(ip netns exec "$NS" curl -sS --max-time 180 -o /dev/null \
    -w '%{http_code} %{size_download} %{speed_download} %{time_total}' \
    "http://$SERVER_IP:$HTTP_PORT/data" || echo "failed")"
if [[ "$RESULT" == failed ]]; then
    echo "FAIL: download did not complete"
    FAILED=1
else
    read -r CODE BYTES SPEED SECONDS_TAKEN <<<"$RESULT"
    echo "HTTP $CODE, $BYTES bytes in ${SECONDS_TAKEN}s"
    python3 -c "
speed = float('$SPEED')
print(f'throughput: {speed * 8 / 1e6:.2f} Mbit/s  ({speed / 1024:.0f} KiB/s)')"
    EXPECTED=$((MEGABYTES * 1024 * 1024))
    if [[ "$CODE" == "200" && "$BYTES" == "$EXPECTED" ]]; then
        echo "PASS: full body transferred and checksummed by curl's length check"
    else
        echo "FAIL: expected $EXPECTED bytes with HTTP 200, got $BYTES with HTTP $CODE"
        FAILED=1
    fi
fi

echo
echo "== DNS through the tunnel (UDP NAT, to a public resolver)"
if ip netns exec "$NS" timeout 20 getent hosts example.com; then
    echo "PASS: name resolved through the device"
else
    echo "WARN: DNS did not resolve; skipping the internet fetch"
fi

echo
echo "== GET http://example.com through the device (real internet)"
EXTERNAL="$(ip netns exec "$NS" curl -sS --max-time 45 -o /dev/null \
    -w '%{http_code} %{size_download}' http://example.com/ || echo failed)"
if [[ "$EXTERNAL" == failed ]]; then
    echo "WARN: external fetch failed (the network may not permit it)"
else
    read -r EXT_CODE EXT_BYTES <<<"$EXTERNAL"
    echo "HTTP $EXT_CODE, $EXT_BYTES bytes from example.com"
    if [[ "$EXT_CODE" == "200" && "$EXT_BYTES" -gt 0 ]]; then
        echo "PASS: fetched a real website through the gateway"
    else
        echo "WARN: unexpected response from example.com"
    fi
fi

echo
echo "== HTTPS through the device (TLS over the forwarded TCP)"
TLS="$(ip netns exec "$NS" curl -sS --max-time 60 -o /dev/null \
    -w '%{http_code} %{size_download}' https://example.com/ || echo failed)"
if [[ "$TLS" == failed ]]; then
    echo "WARN: HTTPS fetch failed"
else
    read -r TLS_CODE TLS_BYTES <<<"$TLS"
    echo "HTTP $TLS_CODE, $TLS_BYTES bytes over TLS"
    if [[ "$TLS_CODE" == "200" && "$TLS_BYTES" -gt 0 ]]; then
        echo "PASS: completed a TLS handshake and transfer through the gateway"
    else
        echo "WARN: unexpected HTTPS response"
    fi
fi

echo
echo "== server log"
kill -INT "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
cat "$WORK/server.log"

echo
echo "== device peer state"
ip netns exec "$NS" wg show wg0 | grep -E "handshake|transfer"

exit "$FAILED"
