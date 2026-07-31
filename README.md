# esp-gateway

ESP32-C6 firmware (Rust, `no_std`, Embassy) that joins a [Tailscale](https://tailscale.com)
network and acts as an **exit node**: WireGuard data plane, ts2021 control plane, and NAT out
the WiFi station uplink.

The target is compatibility with **both** hosted Tailscale and self-hosted
[Headscale](https://headscale.net), at their current versions. Those are different problems —
Headscale on a LAN accepts plain HTTP and tolerates a client that never relays, while
`controlplane.tailscale.com` requires TLS and DERP — so compatibility with one is not evidence
about the other, and the test framework reports them separately.

## Why this is possible

- **MicroLink** ([CamM2325/microlink](https://github.com/CamM2325/microlink), MIT) already does
  the full thing in C on an ESP32-C3 — ts2021 + disco + DERP + WireGuard. It is our de facto
  protocol specification.
- **alfs/tailscale-iot** demonstrates Headscale working without DERP on a LAN, where peers
  disco-ping each other directly.
- Every cryptographic primitive WireGuard and ts2021 need exists as a `no_std` Rust crate
  (`x25519-dalek`, `chacha20poly1305`, `blake2`, `crypto_box`). What does *not* exist is a
  published `no_std` WireGuard implementation, so `crates/wg-core` is ours.

## Compatibility

`tests/` holds a framework that measures this project against real Headscale and a real
Tailscale client rather than against our own assumptions. It enumerates every behaviour a
compatible node must exhibit and gives each one a status, so the gap is explicit and
countable rather than vague.

```sh
scripts/conformance.sh --capture   # start the references, capture ground truth, print the matrix
```

**Currently 9 of 34 behaviours verified.** The data plane and exit-node forwarding are done;
the entire control plane is not. See `tests/README.md` for what the framework has already
established about the real servers — including that Headscale v0.29.3 rejects any client
advertising a capability version below 113.

## Layout

```
firmware/         ESP32-C6 binary: WiFi STA, embassy-net, tunnel, NAT
tests/            compatibility framework: reference lab, ground-truth vectors
crates/ts-conformance  the compatibility matrix
crates/wg-core    sans-io no_std no-alloc WireGuard core (handshake, transport, timers)
crates/micro-h2   minimal no-alloc HTTP/2 client, generic over embedded-io-async
crates/ts-control ts2021 client: Noise IK + controlbase framing + register/map logic
harness/          no_std binary for x86_64-unknown-linux-none: runs the SAME library
                  crates against real wg-quick / Headscale on the dev machine, no ESP32
```

## Design rules

**No allocation.** No project code uses `alloc` — no `Box`, `Vec`, or `String` in our modules.
Buffers are static (`static_cell`), collections are `heapless`. The single exception is
`esp-alloc`, kept solely as the private heap the esp-radio WiFi C blob mallocs from; if a future
esp-radio release drops that requirement, `esp-alloc` goes too.

**Build on embedded async traits.** Everything above the HAL is generic over
`embedded-io-async` (byte streams) and `embedded-nal-async` (TCP/UDP) rather than concrete
embassy-net types. embassy-net sockets already implement these traits, so every layer is
host-testable on std and reusable off the ESP32.

**Reuse before writing.** Before starting any crate, look for an existing near-miss with an
active maintainer and prefer contributing or forking over rewriting. Specifically:
[reqwless](https://github.com/drogue-iot/reqwless) for the HTTP/2 work, and
[rustyguard](https://github.com/conradludgate/rustyguard) — which is `no_std` sans-io and
exactly the right shape, but currently unpublished and unlicensed — for WireGuard. Never
hand-roll a cryptographic primitive.

**Memory budget.** The C6 has 512 KB HP SRAM (~448 KB usable) and the radio blob's heap takes
64–96 KB of it. Every buffer size is a named constant in a per-crate budget module, and the
x86 harness uses the *same* constants so it cannot silently rely on space the C6 lacks. Working
targets: WireGuard sessions ≤ 8 KB, tunnel UDP buffers ~8 KB, NAT table ≤ 8 KB (~256 entries),
HTTP/2 frame + HPACK ≤ 20 KB, netmap staging ≤ 32 KB (streamed, never fully buffered),
embassy-net resources ~24 KB. `.data + .bss` is capped at 200 KB and checked after every
milestone.

## Testing without hardware

`harness/` targets `x86_64-unknown-linux-none` (tier 3: Linux syscall ABI, no libc, no std). It
supplies its own `_start`, reaches the kernel through `rustix` with `default-features = false`,
and runs the identical library crates against a real `wg-quick` peer on the development machine.
On top of that sits a small reactor — one `poll` call, no allocator, no threads — which is what
the async control plane will be built on. The firmware stays on stable Rust; only the harness
needs nightly, for `-Z build-std`.

```sh
cargo test                                     # host unit tests for every crates/* library
harness/…/harness selftest /tmp/harness-state  # the runtime itself: reactor, sockets, storage
sudo scripts/interop-wireguard.sh              # M2 against real kernel WireGuard (std example)
sudo scripts/interop-wireguard.sh harness      # the same, via the no_std no-libc harness
sudo scripts/interop-wireguard.sh initiator    # the harness starts the handshake; kernel answers
```

The interop script creates a network namespace, configures a real kernel WireGuard interface
inside it, and requires both a completed handshake and a successful in-tunnel ping. In
`initiator` mode the kernel peer is configured with *no* endpoint, so it cannot start a
handshake — a completed one proves ours was accepted. Testing against the reference
implementation rather than against ourselves is what caught the one protocol detail we had wrong
— see `crates/wg-core/README.md`.

## Milestones

| ID | Goal | Verified by |
|----|------|-------------|
| M1 ✅ | WiFi STA + DHCP | device gets an IP, answers `ping` |
| M2 ✅ | WireGuard responder + in-tunnel ICMP | `wg show` reports a handshake; `ping 10.99.0.1` |
| M3a ✅ | NAT out the uplink (UDP) | echo server sees the device's own IP; 4.3 Mbit/s |
| M3 ✅ | TCP forwarding | `curl` and `https://` through the tunnel from the device's IP |
| M3b | `Driver` shim (only if raw sockets prove insufficient) | 30 min soak |
| P0 | Headscale lab over plain HTTP, pcap ground truth | captured `/ts2021` session as test vectors |
| P1 | Machine/node/disco keys + Noise IK + controlbase | host test completes a real `/ts2021` handshake |
| P2 | `micro-h2` + `RegisterRequest` with a preauth key | node appears in `headscale nodes list` |
| P3 | `MapRequest` long-poll + streaming netmap parse | tailnet ping between peers |
| P4 | Disco on the shared WireGuard socket | connections report as "direct" |
| P5 | Exit-node advertisement + route approval | laptop routes all traffic through the device |

M1 and M2 are complete and verified on real hardware: an ESP32-C6 joins the WiFi network, takes
a DHCP lease, and completes a WireGuard handshake with the Linux kernel's implementation, which
then pings it through the tunnel. The same code passes the same test on the host and in the
harness.

## Running it on a device

Configuration reaches the firmware through `env!`, and `firmware/.cargo/config.toml` holds only
placeholders. Real values live in a gitignored `.env` at the repository root — copy
`.env.example` and fill it in.

```sh
scripts/flash.sh                               # build and flash, then monitor
sudo scripts/device-peer.sh up 192.168.6.163   # this machine becomes the peer; pings the tunnel
sudo scripts/device-peer.sh down               # remove the interface again
sudo scripts/bench-exit.sh 192.168.6.163       # UDP exit-node throughput benchmark
sudo scripts/test-http.sh 192.168.6.163        # HTTP/HTTPS forwarding through the device
```

The firmware still only responds; it never starts a handshake, so whatever sits on the other end
must be able to initiate. `wg-core` itself now does both roles — `Device::set_initiating` turns a
peer from one this device only answers into one it will start handshakes with, which is what a
mesh needs — and `scripts/interop-wireguard.sh initiator` verifies that half against the kernel.

## Forwarding

Both UDP and TCP are forwarded out of the WiFi uplink from the device's own address, so it works
as a general exit node: a client whose default route points into the tunnel resolves names,
fetches HTTP, and completes TLS handshakes, all appearing to the outside world as the ESP32.

The two protocols are translated differently. A UDP flow gets an ordinary `UdpSocket` on the
station interface, so the stack writes the outer headers itself and no checksum fixup is needed.
TCP cannot work that way — a `TcpSocket` would terminate the connection on the device instead of
passing it through — so segments are translated individually over a raw socket, with incremental
checksum updates (RFC 1624) and MSS clamping to the tunnel's MTU.

The plan expected TCP to need a custom `Driver` shim, on the theory that smoltcp would answer
forwarded segments with its own RST. It does not: smoltcp suppresses the RST for any packet a
raw socket consumes, so the shim turned out to be unnecessary.

MSS clamping matters more than it looks. Without it a connection opens normally and then hangs
the instant it carries a full-size segment, because that segment exceeds the tunnel MTU and is
silently dropped.

## Measured throughput

`scripts/bench-exit.sh` measures UDP.
`scripts/bench-exit.sh` runs a client in a network namespace so its traffic genuinely takes the
tunnel, and an echo server that reports the source address it observes — which is the actual
proof of translation, and reads as the device's LAN address rather than the tunnel client's.

With 1024-byte payloads on 2.4 GHz WiFi: **4.3 Mbit/s peak** through the device (2.16 Mbit/s of
payload in each direction, 264 packets/s), and 3.85 Mbit/s sustained below 5% loss.

HTTP downloads through the same path run at **2.6–3.4 Mbit/s** (a 2 MiB body in 5–6 s),
measured by `scripts/test-http.sh`.

The limit is not the cryptography. Sweeping payload size shows a fixed cost of roughly 2.3 ms
per packet on top of a much smaller per-byte cost, which is the signature of a serialized path:
the tunnel task handles one packet from end to end — decrypt, forward, await the reply, encrypt
— before starting the next, so throughput tracks the WiFi round trip rather than the CPU.
Splitting the two directions into separate tasks so they pipeline is the obvious next
optimisation, and is where any real gain lives.

## Scope limits (v1)

IPv4 only. MTU 1280 on the client side, no fragmentation. WireGuard responder-only — the peer
always initiates, and rekeying works by expiring the session so the peer re-initiates. No
cookie/mac2 DoS machinery (the replay window *is* implemented). Throughput of a few Mbps.

## References

- `tailscale.com/control/controlbase`, `tailcfg.go`, `disco.go`
- `headscale` `hscontrol/noise.go`, `hscontrol/poll.go`
- [tailscale/tailscale-rs](https://github.com/tailscale/tailscale-rs) for wire formats

## License

Dual-licensed under MIT or Apache-2.0, at your option. Each `crates/*` library is written to be
independently publishable under the same terms.
