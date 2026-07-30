# esp-gateway

ESP32-C6 firmware (Rust, `no_std`, Embassy) that joins a [Tailscale](https://tailscale.com)
network coordinated by a self-hosted [Headscale](https://headscale.net) server on the LAN and
acts as an **exit node**: WireGuard data plane, ts2021 control plane, and NAT out the WiFi
station uplink.

## Why this is possible

- **MicroLink** ([CamM2325/microlink](https://github.com/CamM2325/microlink), MIT) already does
  the full thing in C on an ESP32-C3 — ts2021 + disco + DERP + WireGuard. It is our de facto
  protocol specification.
- **alfs/tailscale-iot** demonstrates Headscale working without DERP on a LAN, where peers
  disco-ping each other directly.
- Every cryptographic primitive WireGuard and ts2021 need exists as a `no_std` Rust crate
  (`x25519-dalek`, `chacha20poly1305`, `blake2`, `crypto_box`). What does *not* exist is a
  published `no_std` WireGuard implementation, so `crates/wg-core` is ours.

## Layout

```
firmware/         ESP32-C6 binary: WiFi STA, embassy-net, tunnel, NAT
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
supplies `_start`, raw syscall wrappers for sockets and timers, and `embedded-io-async` /
`embedded-nal-async` implementations over them — then runs the identical library crates against
a real `wg-quick` peer and a real Headscale on the development machine. The firmware stays on
stable Rust; only the harness needs nightly, for `-Zbuild-std=core`.

Each library crate additionally gets ordinary std `cargo test` on the host.

## Milestones

| ID | Goal | Verified by |
|----|------|-------------|
| M1 | WiFi STA + DHCP | device gets an IP, answers `ping` |
| M2 | WireGuard responder + in-tunnel ICMP | `wg show` reports a handshake; `ping 10.99.0.1` |
| M3a | NAT via raw sockets (likely ICMP + UDP only) | `ping 1.1.1.1`, `dig @1.1.1.1` from the peer |
| M3b | NAT via an embassy-net `Driver` shim | `curl https://…` through the tunnel; 30 min soak |
| P0 | Headscale lab over plain HTTP, pcap ground truth | captured `/ts2021` session as test vectors |
| P1 | Machine/node/disco keys + Noise IK + controlbase | host test completes a real `/ts2021` handshake |
| P2 | `micro-h2` + `RegisterRequest` with a preauth key | node appears in `headscale nodes list` |
| P3 | `MapRequest` long-poll + streaming netmap parse | tailnet ping between peers |
| P4 | Disco on the shared WireGuard socket | connections report as "direct" |
| P5 | Exit-node advertisement + route approval | laptop routes all traffic through the device |

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
