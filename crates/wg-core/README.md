# wg-core

A sans-io [WireGuard](https://www.wireguard.com) protocol core: `no_std`,
allocation-free, and independent of any socket API.

`Device` never touches a socket, a clock, or a random number generator of its
own. You hand it received datagrams together with the current time and a source
of randomness; it hands back `Action`s describing what to send or deliver. The
same code therefore runs inside an Embassy task on a microcontroller and under
`cargo test` on a laptop.

```rust
use wg_core::{Action, Device, Instant, Rng};

let mut device: Device<4> = Device::new(static_private_key);
let peer = device.add_peer(peer_public_key, None)?;

match device.handle_udp(&datagram, Instant(now_millis), &mut rng, &mut out)? {
    Action::Send { peer, data } => socket.send_to(data, endpoint_of(peer)),
    Action::Receive { peer, packet } => deliver(peer, packet),
    Action::None => {}
}
# Ok::<(), wg_core::Error>(())
```

## Scope

This is a **responder**: the peer always initiates. There is no rekey logic
beyond letting a session expire, at which point the peer notices and starts a
fresh handshake. The cookie/`mac2` denial-of-service mechanism is not
implemented; a per-device handshake rate limit stands in for it, applied after
the cheap `mac1` screen so that forged packets cannot spend the budget that
protects the X25519 work. Replay protection *is* implemented in full, with a
1024-packet sliding window.

Implemented: Noise IKpsk2 responder handshake, ChaCha20-Poly1305 transport,
sliding-window replay protection, passive keepalives, session expiry, and
current/previous session slots so a rekey does not drop packets still in flight.

Not implemented: initiating handshakes, cookies, roaming logic (the caller owns
endpoints), and anything above IP.

## Verification

The handshake is checked against the reference implementation, not only against
itself. `scripts/interop-wireguard.sh` in the parent repository stands up a real
kernel WireGuard interface in a network namespace, points it at the `responder`
example, and requires both a completed handshake and a successful in-tunnel
ping. The in-process tests in `src/tests.rs` then drive the same ladder the
kernel accepted, so they run in CI without root.

One finding worth recording, because it costs an afternoon otherwise: the Noise
construction string is

```text
Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
```

with the cipher spelled `ChaChaPoly`, the short name from the Noise
specification — **not** `ChaCha20Poly1305`, which is how WireGuard's own paper
writes it in prose. The Linux kernel pins it as `static const u8
handshake_name[37]`, and 37 is the length of the short form. Getting this wrong
changes the initial chaining key, and the only symptom is that the first AEAD
tag check fails, a long way from the cause.

## Memory

Every buffer size is a named constant in `budget`, so the cost is auditable and
a host test cannot silently assume space the target does not have. A `Device`
holds `PEERS` peers; each peer costs two sessions of roughly 200 bytes. The
largest single buffer a caller must provide is `MAX_DATAGRAM_LEN` (1312 bytes),
enough for a full 1280-byte inner packet plus header, padding, and tag.

## Dependencies

Only cryptographic primitives and `heapless`, all `no_std`: `x25519-dalek`,
`chacha20poly1305`, `blake2`, `hmac`, `subtle`, `zeroize`. Nothing is
hand-rolled. `#![forbid(unsafe_code)]`.

Randomness is supplied through a local `Rng` trait rather than `rand_core`,
because depending on `rand_core` would pin a particular major version onto every
consumer, and a hardware RNG has nothing else in common with a test generator.

## License

MIT OR Apache-2.0, at your option.
