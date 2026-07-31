//! An in-process initiator, driving [`Device`] through complete sessions.
//!
//! These tests need no root, no network, and no hardware, so they run in CI.
//! What makes them trustworthy is that the ladder [`Initiator`] implements was
//! itself validated against the Linux kernel's WireGuard: the same construction
//! was sent to a real `wg` interface, which accepted it and replied. See
//! `scripts/interop-wireguard.sh`, which re-runs that check end to end.
//!
//! The constants and label strings are restated here rather than imported from
//! [`crate::noise`], so that a typo in one is caught by disagreement with the
//! other instead of being cancelled out.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{self, Key};
use crate::messages::{initiation, response};
use crate::{Action, Device, Error, Instant, PeerId, Rng};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

/// A generator that is deterministic but not constant, so that tests are
/// reproducible while still exercising distinct session indices and ephemeral
/// keys on every handshake.
struct TestRng(u64);

impl Rng for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            // SplitMix64, chosen only for being short and well-distributed.
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *byte = (z ^ (z >> 31)) as u8;
        }
    }
}

/// The initiator half of the protocol, which `wg-core` deliberately does not
/// implement in production.
struct Initiator {
    static_private: StaticSecret,
    static_public: PublicKey,
    responder_public: PublicKey,
    preshared_key: Key,
    ephemeral: StaticSecret,
    chaining_key: Key,
    hash: Key,
    local_index: u32,
    peer_index: u32,
    sending: Key,
    receiving: Key,
    send_counter: u64,
}

impl Initiator {
    fn new(static_private: [u8; 32], responder_public: [u8; 32], preshared_key: Option<Key>) -> Self {
        let static_private = StaticSecret::from(static_private);
        Self {
            static_public: PublicKey::from(&static_private),
            static_private,
            responder_public: PublicKey::from(responder_public),
            preshared_key: preshared_key.unwrap_or([0u8; 32]),
            ephemeral: StaticSecret::from([0u8; 32]),
            chaining_key: [0u8; 32],
            hash: [0u8; 32],
            local_index: 0,
            peer_index: 0,
            sending: [0u8; 32],
            receiving: [0u8; 32],
            send_counter: 0,
        }
    }

    fn create_initiation(&mut self, ephemeral: [u8; 32], timestamp: [u8; 12]) -> [u8; initiation::LEN] {
        self.ephemeral = StaticSecret::from(ephemeral);
        self.local_index = 0x1122_3344;

        self.chaining_key = crypto::hash(&[CONSTRUCTION]);
        self.hash = crypto::hash(&[&crypto::hash(&[&self.chaining_key, IDENTIFIER])[..], self.responder_public.as_bytes()]);

        let mut msg = [0u8; initiation::LEN];
        msg[0] = 1;
        msg[initiation::SENDER].copy_from_slice(&self.local_index.to_le_bytes());

        let ephemeral_public = PublicKey::from(&self.ephemeral);
        msg[initiation::EPHEMERAL].copy_from_slice(ephemeral_public.as_bytes());
        self.chaining_key = crypto::kdf1(&self.chaining_key, ephemeral_public.as_bytes());
        self.hash = crypto::hash(&[&self.hash, ephemeral_public.as_bytes()]);

        let (ck, key) = crypto::kdf2(
            &self.chaining_key,
            &crypto::dh(&self.ephemeral, &self.responder_public).unwrap(),
        );
        self.chaining_key = ck;
        let sealed = &mut msg[initiation::STATIC];
        sealed[..32].copy_from_slice(self.static_public.as_bytes());
        let tag = crypto::aead_seal(&key, 0, &self.hash, &mut sealed[..32]);
        sealed[32..].copy_from_slice(&tag);
        self.hash = crypto::hash(&[&self.hash, &msg[initiation::STATIC]]);

        let (ck, key) = crypto::kdf2(
            &self.chaining_key,
            &crypto::dh(&self.static_private, &self.responder_public).unwrap(),
        );
        self.chaining_key = ck;
        let sealed = &mut msg[initiation::TIMESTAMP];
        sealed[..12].copy_from_slice(&timestamp);
        let tag = crypto::aead_seal(&key, 0, &self.hash, &mut sealed[..12]);
        sealed[12..].copy_from_slice(&tag);
        self.hash = crypto::hash(&[&self.hash, &msg[initiation::TIMESTAMP]]);

        let mac1_key = crypto::hash(&[LABEL_MAC1, self.responder_public.as_bytes()]);
        let mac1 = crypto::mac(&mac1_key, &[&msg[initiation::MAC1_INPUT]]);
        msg[initiation::MAC1].copy_from_slice(&mac1);
        msg
    }

    fn consume_response(&mut self, msg: &[u8]) -> Result<(), Error> {
        assert_eq!(msg.len(), response::LEN);
        assert_eq!(msg[0], 2);
        self.peer_index = crate::messages::get_u32(&msg[response::SENDER]);

        let mut ephemeral_bytes = [0u8; 32];
        ephemeral_bytes.copy_from_slice(&msg[response::EPHEMERAL]);
        let peer_ephemeral = PublicKey::from(ephemeral_bytes);

        self.chaining_key = crypto::kdf1(&self.chaining_key, peer_ephemeral.as_bytes());
        self.hash = crypto::hash(&[&self.hash, peer_ephemeral.as_bytes()]);
        self.chaining_key = crypto::kdf1(
            &self.chaining_key,
            &crypto::dh(&self.ephemeral, &peer_ephemeral)?,
        );
        self.chaining_key = crypto::kdf1(
            &self.chaining_key,
            &crypto::dh(&self.static_private, &peer_ephemeral)?,
        );

        let (ck, tau, key) = crypto::kdf3(&self.chaining_key, &self.preshared_key);
        self.chaining_key = ck;
        self.hash = crypto::hash(&[&self.hash, &tau]);
        crypto::aead_open(&key, 0, &self.hash, &mut [], &msg[response::EMPTY])?;

        let (sending, receiving) = crypto::kdf2(&self.chaining_key, &[]);
        self.sending = sending;
        self.receiving = receiving;
        Ok(())
    }

    fn seal(&mut self, packet: &[u8], out: &mut [u8]) -> usize {
        let padded = packet.len().next_multiple_of(16);
        let counter = self.send_counter;
        self.send_counter += 1;
        self.seal_with_counter(packet, counter, out);
        16 + padded + 16
    }

    fn seal_with_counter(&mut self, packet: &[u8], counter: u64, out: &mut [u8]) -> usize {
        let padded = packet.len().next_multiple_of(16);
        out[0] = 4;
        out[1..4].fill(0);
        out[4..8].copy_from_slice(&self.peer_index.to_le_bytes());
        out[8..16].copy_from_slice(&counter.to_le_bytes());
        out[16..16 + padded].fill(0);
        out[16..16 + packet.len()].copy_from_slice(packet);
        let tag = crypto::aead_seal(&self.sending, counter, &[], &mut out[16..16 + padded]);
        out[16 + padded..16 + padded + 16].copy_from_slice(&tag);
        16 + padded + 16
    }

    fn open(&self, datagram: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let counter = crate::messages::get_u64(&datagram[8..16]);
        let body = &datagram[16..];
        let len = body.len() - 16;
        out[..len].copy_from_slice(&body[..len]);
        crypto::aead_open(&self.receiving, counter, &[], &mut out[..len], &body[len..])?;
        Ok(len)
    }
}

/// A syntactically valid IPv4 packet, since the core reads the header to strip
/// WireGuard's padding.
fn ipv4_packet(payload_len: usize) -> [u8; 64] {
    let mut packet = [0u8; 64];
    packet[0] = 0x45;
    let total = 20 + payload_len;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&[10, 99, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 99, 0, 2]);
    for (i, b) in packet[20..total].iter_mut().enumerate() {
        *b = i as u8;
    }
    packet
}

const RESPONDER_KEY: [u8; 32] = [0x42; 32];
const INITIATOR_KEY: [u8; 32] = [0x17; 32];

/// Bring a device and an initiator to the point where both hold session keys.
fn handshake(psk: Option<Key>, now: Instant) -> (Device<2>, Initiator, PeerId, TestRng) {
    let mut rng = TestRng(0xdead_beef);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    let mut initiator = Initiator::new(INITIATOR_KEY, device.public_key(), psk);
    let peer = device
        .add_peer(initiator.static_public.to_bytes(), psk)
        .unwrap();

    let msg = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    let Action::Send { data, .. } = device.handle_udp(&msg, now, &mut rng, &mut out).unwrap() else {
        panic!("an initiation must produce a response");
    };
    initiator.consume_response(data).unwrap();
    (device, initiator, peer, rng)
}

#[test]
fn initial_constants_match_the_reference_implementation() {
    // Verified two ways: these are the values the Linux kernel's WireGuard
    // uses, and a handshake built on them was accepted by a real `wg`
    // interface. See `scripts/interop-wireguard.sh`.
    assert_eq!(CONSTRUCTION.len(), 37);
    assert_eq!(IDENTIFIER.len(), 34);
    assert_eq!(
        crypto::hash(&[CONSTRUCTION]),
        hex_literal("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"),
    );
    assert_eq!(
        crypto::hash(&[&crypto::hash(&[CONSTRUCTION])[..], IDENTIFIER]),
        hex_literal("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"),
    );
}

fn hex_literal(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn completes_a_handshake_and_carries_data_both_ways() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, _) = handshake(None, now);

    // Initiator to responder.
    let packet = ipv4_packet(8);
    let len = 28;
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..len], &mut datagram);

    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    let Action::Receive {
        peer: from,
        packet: received,
    } = device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).unwrap()
    else {
        panic!("a data message must be delivered");
    };
    assert_eq!(from, peer);
    // Padding is stripped back to the length in the IP header.
    assert_eq!(received, &packet[..len]);

    // Responder back to initiator.
    let reply = ipv4_packet(16);
    let reply_len = 36;
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    let Action::Send { data, .. } = device
        .encapsulate(peer, &reply[..reply_len], now, &mut out)
        .unwrap()
    else {
        panic!("encapsulate must produce a datagram");
    };
    let mut plain = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.open(data, &mut plain).unwrap();
    assert_eq!(&plain[..reply_len], &reply[..reply_len]);
    // What the initiator sees is still padded; only our side strips it.
    assert_eq!(n, reply_len.next_multiple_of(16));
}

#[test]
fn a_preshared_key_is_required_by_both_sides() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, _) = handshake(Some([0x99; 32]), now);
    let packet = ipv4_packet(8);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(matches!(
        device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out),
        Ok(Action::Receive { peer: p, .. }) if p == peer
    ));
}

#[test]
fn a_mismatched_preshared_key_breaks_the_handshake() {
    let now = Instant(1_000);
    let mut rng = TestRng(7);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    let mut initiator = Initiator::new(INITIATOR_KEY, device.public_key(), Some([0x01; 32]));
    device
        .add_peer(initiator.static_public.to_bytes(), Some([0x02; 32]))
        .unwrap();

    let msg = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    // The responder happily builds a response; it is the initiator that
    // discovers the mismatch, because the PSK only enters the ladder there.
    let Action::Send { data, .. } = device.handle_udp(&msg, now, &mut rng, &mut out).unwrap() else {
        panic!("expected a response");
    };
    assert_eq!(initiator.consume_response(data), Err(Error::Decryption));
}

#[test]
fn rejects_a_replayed_initiation() {
    let now = Instant(1_000);
    let mut rng = TestRng(3);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    let mut initiator = Initiator::new(INITIATOR_KEY, device.public_key(), None);
    device
        .add_peer(initiator.static_public.to_bytes(), None)
        .unwrap();

    let msg = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(device.handle_udp(&msg, now, &mut rng, &mut out).is_ok());

    // Same timestamp replayed, past the rate limit so that is not what trips.
    let later = Instant(now.0 + 10_000);
    assert_eq!(
        device.handle_udp(&msg, later, &mut rng, &mut out).unwrap_err(),
        Error::StaleTimestamp
    );
}

#[test]
fn rate_limits_back_to_back_handshakes() {
    let now = Instant(1_000);
    let mut rng = TestRng(3);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    let mut initiator = Initiator::new(INITIATOR_KEY, device.public_key(), None);
    device
        .add_peer(initiator.static_public.to_bytes(), None)
        .unwrap();

    let first = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(device.handle_udp(&first, now, &mut rng, &mut out).is_ok());

    let second = initiator.create_initiation([0x34; 32], *b"timestamp002");
    assert_eq!(
        device
            .handle_udp(&second, Instant(now.0 + 1), &mut rng, &mut out)
            .unwrap_err(),
        Error::RateLimited
    );
}

#[test]
fn rejects_an_initiation_addressed_to_a_different_responder() {
    let now = Instant(1_000);
    let mut rng = TestRng(3);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    let mut initiator = Initiator::new(INITIATOR_KEY, [0x77; 32], None);
    device
        .add_peer(initiator.static_public.to_bytes(), None)
        .unwrap();

    let msg = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(
        device.handle_udp(&msg, now, &mut rng, &mut out).unwrap_err(),
        Error::InvalidMac
    );
}

#[test]
fn rejects_an_unconfigured_peer() {
    let now = Instant(1_000);
    let mut rng = TestRng(3);
    let mut device: Device<2> = Device::new(RESPONDER_KEY);
    // A device with no peers at all: mac1 still passes, identity does not.
    let mut initiator = Initiator::new(INITIATOR_KEY, device.public_key(), None);
    let msg = initiator.create_initiation([0x33; 32], *b"timestamp001");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(
        device.handle_udp(&msg, now, &mut rng, &mut out).unwrap_err(),
        Error::UnknownPeer
    );
}

#[test]
fn rejects_a_replayed_data_packet() {
    let now = Instant(1_000);
    let (mut device, mut initiator, _, _) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);

    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).is_ok());
    assert_eq!(
        device
            .handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out)
            .unwrap_err(),
        Error::Replay
    );
}

#[test]
fn rejects_a_tampered_data_packet_without_consuming_the_counter() {
    let now = Instant(1_000);
    let (mut device, mut initiator, _, _) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);

    let mut corrupted = datagram;
    corrupted[20] ^= 0xff;
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(
        device
            .handle_udp(&corrupted[..n], now, &mut TestRng(1), &mut out)
            .unwrap_err(),
        Error::Decryption
    );
    // The genuine packet with the same counter must still be accepted, or a
    // forgery would be able to knock out legitimate traffic.
    assert!(device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).is_ok());
}

#[test]
fn accepts_data_that_arrives_out_of_order() {
    let now = Instant(1_000);
    let (mut device, mut initiator, _, _) = handshake(None, now);
    let packet = ipv4_packet(8);

    let mut first = [0u8; crate::MAX_DATAGRAM_LEN];
    let n1 = initiator.seal(&packet[..28], &mut first);
    let mut second = [0u8; crate::MAX_DATAGRAM_LEN];
    let n2 = initiator.seal(&packet[..28], &mut second);

    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(device.handle_udp(&second[..n2], now, &mut TestRng(1), &mut out).is_ok());
    assert!(device.handle_udp(&first[..n1], now, &mut TestRng(1), &mut out).is_ok());
}

#[test]
fn will_not_send_before_the_peer_confirms_the_session() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, _) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];

    assert!(!device.is_connected(peer, now));
    assert_eq!(
        device.encapsulate(peer, &packet[..28], now, &mut out).unwrap_err(),
        Error::Unconfirmed
    );

    // One packet from the peer proves it derived the same keys.
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);
    device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).unwrap();

    assert!(device.is_connected(peer, now));
    assert!(device.encapsulate(peer, &packet[..28], now, &mut out).is_ok());
}

#[test]
fn a_keepalive_is_authenticated_but_delivers_nothing() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, _) = handshake(None, now);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&[], &mut datagram);

    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(matches!(
        device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out),
        Ok(Action::None)
    ));
    // It still counts as confirmation that the peer holds the right keys.
    assert!(device.is_connected(peer, now));
}

#[test]
fn sends_a_keepalive_after_receiving_data_and_staying_quiet() {
    let now = Instant(1_000);
    let (mut device, mut initiator, _, _) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).unwrap();

    // Not yet due.
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(matches!(device.poll_timers(Instant(now.0 + 1_000), &mut out), Action::None));

    let due = Instant(now.0 + timers::KEEPALIVE_TIMEOUT_MS);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    let Action::Send { data, .. } = device.poll_timers(due, &mut out) else {
        panic!("a keepalive was due");
    };
    // A keepalive is a data message with an empty plaintext.
    assert_eq!(data[0], 4);
    assert_eq!(data.len(), 32);
    let mut plain = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(initiator.open(data, &mut plain).unwrap(), 0);

    // Having sent one, another is not immediately due.
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(matches!(device.poll_timers(due, &mut out), Action::None));
}

#[test]
fn a_session_expires_and_stops_being_usable() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, _) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut datagram = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut datagram);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    device.handle_udp(&datagram[..n], now, &mut TestRng(1), &mut out).unwrap();
    assert!(device.is_connected(peer, now));

    let expired = Instant(now.0 + timers::REJECT_AFTER_TIME_MS);
    assert!(!device.is_connected(peer, expired));
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(
        device.encapsulate(peer, &packet[..28], expired, &mut out).unwrap_err(),
        Error::NoSession
    );
}

#[test]
fn a_rekey_keeps_the_old_session_alive_for_packets_still_in_flight() {
    let now = Instant(1_000);
    let (mut device, mut initiator, peer, mut rng) = handshake(None, now);
    let packet = ipv4_packet(8);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];

    // Confirm the first session, then seal a packet under it that will be
    // "delayed" past the rekey.
    let mut first = [0u8; crate::MAX_DATAGRAM_LEN];
    let n = initiator.seal(&packet[..28], &mut first);
    device.handle_udp(&first[..n], now, &mut TestRng(1), &mut out).unwrap();
    let mut delayed = [0u8; crate::MAX_DATAGRAM_LEN];
    let delayed_len = initiator.seal(&packet[..28], &mut delayed);

    // A fresh handshake supersedes it.
    let later = Instant(now.0 + 60_000);
    let mut second_initiator = Initiator::new(INITIATOR_KEY, device.public_key(), None);
    let msg = second_initiator.create_initiation([0x55; 32], *b"timestamp002");
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    let Action::Send { data, .. } = device.handle_udp(&msg, later, &mut rng, &mut out).unwrap()
    else {
        panic!("expected a response");
    };
    second_initiator.consume_response(data).unwrap();

    // The delayed packet, sealed under the old keys, still opens.
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert!(matches!(
        device.handle_udp(&delayed[..delayed_len], later, &mut TestRng(1), &mut out),
        Ok(Action::Receive { peer: p, .. }) if p == peer
    ));
}

#[test]
fn rejects_messages_that_are_malformed_or_unsupported() {
    let now = Instant(1_000);
    let (mut device, _, _, _) = handshake(None, now);
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];

    assert_eq!(
        device.handle_udp(&[], now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::Malformed
    );
    // A response and a cookie reply are both meaningless to a responder.
    assert_eq!(
        device.handle_udp(&[2, 0, 0, 0], now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(
        device.handle_udp(&[3, 0, 0, 0], now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(
        device.handle_udp(&[9, 0, 0, 0], now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::Malformed
    );
    // Right type, wrong length.
    assert_eq!(
        device.handle_udp(&[1, 0, 0, 0], now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::Malformed
    );
}

#[test]
fn data_for_an_unknown_session_index_is_rejected() {
    let now = Instant(1_000);
    let (mut device, _, _, _) = handshake(None, now);
    let mut datagram = [0u8; 48];
    datagram[0] = 4;
    datagram[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let mut out = [0u8; crate::MAX_DATAGRAM_LEN];
    assert_eq!(
        device.handle_udp(&datagram, now, &mut TestRng(1), &mut out).unwrap_err(),
        Error::UnknownSession
    );
}

use crate::timers;
