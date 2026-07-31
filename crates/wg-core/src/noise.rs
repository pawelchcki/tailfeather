//! The Noise IKpsk2 handshake, responder side.
//!
//! The two functions here follow the WireGuard paper's notation line for line.
//! They are split because the middle of the handshake is where we first learn
//! *who* is talking to us: the initiator's static public key arrives encrypted,
//! and only once it is decrypted can we look up that peer's pre-shared key and
//! finish the exchange. [`consume_initiation`] runs up to that point;
//! [`create_response`] takes it from there.
//!
//! This crate is responder-only, so there is no initiator counterpart. When the
//! session expires the peer notices and starts a new handshake by itself.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto::{self, Key, Mac16, TAG_LEN, TIMESTAMP_LEN};
use crate::messages::{self, initiation, response};

/// The Noise protocol name, which seeds the entire key ladder.
///
/// Note the cipher is spelled `ChaChaPoly`, the short name from the Noise
/// specification, not `ChaCha20Poly1305`. WireGuard's own paper uses the long
/// spelling in prose, but every implementation hashes the short one — the Linux
/// kernel pins it as `static const u8 handshake_name[37]`, and 37 is the length
/// of this string. Getting it wrong changes the initial chaining key, so the
/// handshake fails only at the first AEAD tag check, far from the cause.
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

/// The initial chaining key: `HASH(CONSTRUCTION)`.
fn initial_chaining_key() -> Key {
    crypto::hash(&[CONSTRUCTION])
}

/// The initial hash: `HASH(HASH(CONSTRUCTION) ‖ IDENTIFIER ‖ responder_static)`.
fn initial_hash(responder_static: &PublicKey) -> Key {
    let c = initial_chaining_key();
    let h = crypto::hash(&[&c, IDENTIFIER]);
    crypto::hash(&[&h, responder_static.as_bytes()])
}

/// The key every peer uses to compute `mac1` against us: derived from our own
/// static public key, so it is not a secret — it only proves the sender knew
/// which server it was addressing.
pub fn mac1_key(responder_static: &PublicKey) -> Key {
    crypto::hash(&[LABEL_MAC1, responder_static.as_bytes()])
}

/// Everything learned from a valid handshake initiation, carried forward into
/// [`create_response`].
pub struct Initiation {
    /// The initiator's static public key, now decrypted: this identifies the
    /// peer, and hence which pre-shared key applies.
    pub peer_static: PublicKey,
    /// The initiator's ephemeral public key.
    pub peer_ephemeral: PublicKey,
    /// The initiator's session index, which our replies must echo back.
    pub peer_index: u32,
    /// The initiator's TAI64N timestamp. Callers must reject any value that is
    /// not strictly greater than the last one seen from this peer; that check
    /// needs per-peer state this function does not have.
    pub timestamp: [u8; TIMESTAMP_LEN],
    chaining_key: Zeroizing<Key>,
    hash: Key,
}

/// Check that `msg` is a well-formed initiation carrying a valid `mac1`.
///
/// Split out from [`consume_initiation`] so a caller can run it *before*
/// applying a handshake rate limit. Both checks are a length comparison and one
/// keyed hash, so they cost almost nothing, whereas the rate limiter exists to
/// protect the two X25519 operations that follow. Screening first means traffic
/// from someone who does not even know our public key cannot consume the rate
/// limit budget and lock out a legitimate peer.
///
/// `mac2` is not checked: this implementation never issues cookies, so it has
/// nothing to validate one against.
pub fn verify_initiation_mac1(mac1_key: &Key, msg: &[u8]) -> Result<(), Error> {
    if msg.len() != initiation::LEN || msg[0] != messages::TYPE_INITIATION {
        return Err(Error::Malformed);
    }
    let expected: Mac16 = crypto::mac(mac1_key, &[&msg[initiation::MAC1_INPUT]]);
    if !crypto::ct_eq(&expected, &msg[initiation::MAC1]) {
        return Err(Error::InvalidMac);
    }
    Ok(())
}

/// Verify and decrypt a type-1 handshake initiation.
///
/// `mac1` is checked before any Diffie-Hellman work, so forged packets are
/// discarded for the cost of one keyed hash rather than two X25519 operations.
pub fn consume_initiation(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    mac1_key: &Key,
    msg: &[u8],
) -> Result<Initiation, Error> {
    verify_initiation_mac1(mac1_key, msg)?;

    let mut chaining_key = Zeroizing::new(initial_chaining_key());
    let mut hash = initial_hash(static_public);

    let peer_ephemeral = {
        let mut e = [0u8; 32];
        e.copy_from_slice(&msg[initiation::EPHEMERAL]);
        PublicKey::from(e)
    };
    *chaining_key = crypto::kdf1(&chaining_key, peer_ephemeral.as_bytes());
    hash = crypto::hash(&[&hash, peer_ephemeral.as_bytes()]);

    // Decrypt the initiator's static key using our static and their ephemeral.
    let (ck, key) = crypto::kdf2(
        &chaining_key,
        &crypto::dh(static_private, &peer_ephemeral)?,
    );
    *chaining_key = ck;
    let mut peer_static_bytes = [0u8; 32];
    let sealed_static = &msg[initiation::STATIC];
    peer_static_bytes.copy_from_slice(&sealed_static[..32]);
    crypto::aead_open(
        &key,
        0,
        &hash,
        &mut peer_static_bytes,
        &sealed_static[32..32 + TAG_LEN],
    )?;
    let peer_static = PublicKey::from(peer_static_bytes);
    hash = crypto::hash(&[&hash, sealed_static]);

    // Decrypt the timestamp using both static keys.
    let (ck, key) = crypto::kdf2(&chaining_key, &crypto::dh(static_private, &peer_static)?);
    *chaining_key = ck;
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    let sealed_timestamp = &msg[initiation::TIMESTAMP];
    timestamp.copy_from_slice(&sealed_timestamp[..TIMESTAMP_LEN]);
    crypto::aead_open(
        &key,
        0,
        &hash,
        &mut timestamp,
        &sealed_timestamp[TIMESTAMP_LEN..TIMESTAMP_LEN + TAG_LEN],
    )?;
    hash = crypto::hash(&[&hash, sealed_timestamp]);

    Ok(Initiation {
        peer_static,
        peer_ephemeral,
        peer_index: messages::get_u32(&msg[initiation::SENDER]),
        timestamp,
        chaining_key,
        hash,
    })
}

/// The two directional keys a completed handshake yields.
pub struct TransportKeys {
    /// Opens data the peer sends us.
    pub receiving: Zeroizing<Key>,
    /// Seals data we send the peer.
    pub sending: Zeroizing<Key>,
}

/// Write a type-2 handshake response into `out` and derive the session keys.
///
/// `ephemeral_private` must be freshly random and never reused; reusing it
/// across handshakes would destroy forward secrecy. `preshared_key` is all
/// zeros when the peer has no PSK configured, which is what makes IKpsk2
/// degrade cleanly to plain IK.
///
/// Returns the number of bytes written to `out`.
pub fn create_response(
    initiation: &Initiation,
    preshared_key: &Key,
    local_index: u32,
    ephemeral_private: &StaticSecret,
    out: &mut [u8],
) -> Result<(usize, TransportKeys), Error> {
    let out = out
        .get_mut(..response::LEN)
        .ok_or(Error::BufferTooSmall)?;

    let mut chaining_key = Zeroizing::new(*initiation.chaining_key);
    let mut hash = initiation.hash;

    messages::put_header(out, messages::TYPE_RESPONSE);
    out[response::SENDER].copy_from_slice(&local_index.to_le_bytes());
    out[response::RECEIVER].copy_from_slice(&initiation.peer_index.to_le_bytes());

    let ephemeral_public = PublicKey::from(ephemeral_private);
    out[response::EPHEMERAL].copy_from_slice(ephemeral_public.as_bytes());
    *chaining_key = crypto::kdf1(&chaining_key, ephemeral_public.as_bytes());
    hash = crypto::hash(&[&hash, ephemeral_public.as_bytes()]);

    // Mix in both remaining Diffie-Hellman combinations.
    *chaining_key = crypto::kdf1(
        &chaining_key,
        &crypto::dh(ephemeral_private, &initiation.peer_ephemeral)?,
    );
    *chaining_key = crypto::kdf1(
        &chaining_key,
        &crypto::dh(ephemeral_private, &initiation.peer_static)?,
    );

    // Mix in the pre-shared key, which also contributes to the hash via `tau`.
    let (ck, tau, key) = crypto::kdf3(&chaining_key, preshared_key);
    *chaining_key = ck;
    hash = crypto::hash(&[&hash, &tau]);

    // Seal an empty plaintext: the tag alone proves we completed the handshake.
    let tag = crypto::aead_seal(&key, 0, &hash, &mut []);
    out[response::EMPTY].copy_from_slice(&tag);
    hash = crypto::hash(&[&hash, &out[response::EMPTY]]);
    let _ = hash; // The response is the last message; the hash is not used again.

    let mac1_key = crypto::hash(&[LABEL_MAC1, initiation.peer_static.as_bytes()]);
    let mac1 = crypto::mac(&mac1_key, &[&out[response::MAC1_INPUT]]);
    out[response::MAC1].copy_from_slice(&mac1);
    // We never received a cookie, so mac2 is zero.
    out[response::MAC2].fill(0);

    // KDF2 yields the initiator's (sending, receiving) pair; ours is the
    // mirror image of it.
    let (initiator_sending, initiator_receiving) = crypto::kdf2(&chaining_key, &[]);
    Ok((
        response::LEN,
        TransportKeys {
            receiving: Zeroizing::new(initiator_sending),
            sending: Zeroizing::new(initiator_receiving),
        },
    ))
}

/// Whether `candidate` is strictly newer than `last_seen`.
///
/// TAI64N is big-endian seconds followed by big-endian nanoseconds, so ordinary
/// lexicographic byte comparison is chronological order. WireGuard uses this to
/// reject replayed initiations: a peer's timestamps must strictly increase.
pub fn timestamp_is_newer(candidate: &[u8; TIMESTAMP_LEN], last_seen: &[u8; TIMESTAMP_LEN]) -> bool {
    candidate > last_seen
}
