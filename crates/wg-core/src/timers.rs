//! WireGuard's protocol constants and the timer rules a responder needs.
//!
//! Everything here is a pure function of an injected `now`, so the same logic
//! runs against a monotonic clock on the chip and against a fabricated one in
//! tests.

/// Milliseconds since an arbitrary fixed origin, from a monotonic clock.
///
/// The core never interprets the origin, only differences, so callers are free
/// to use time-since-boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub u64);

impl Instant {
    /// Milliseconds elapsed from `earlier` to `self`, saturating at zero if the
    /// caller's clock went backwards.
    pub fn saturating_since(self, earlier: Instant) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A session older than this must not be used, in either direction.
pub const REJECT_AFTER_TIME_MS: u64 = 180_000;

/// After this long without traffic, a session should be rekeyed. A
/// responder-only implementation cannot initiate, so it instead lets the
/// session expire at [`REJECT_AFTER_TIME_MS`] and waits for the peer to start a
/// new handshake.
pub const REKEY_AFTER_TIME_MS: u64 = 120_000;

/// Having received a data packet, send something back within this long so the
/// peer's NAT mapping and its own timers stay alive.
pub const KEEPALIVE_TIMEOUT_MS: u64 = 10_000;

/// Counter value at which a session must stop being used: `2^64 - 2^13 - 1`.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);

/// Counter value at which a rekey becomes due.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// Reject handshake initiations arriving faster than this, per device.
///
/// Each initiation costs two X25519 operations, which take milliseconds on a
/// 160 MHz RISC-V core, so an unthrottled flood is a cheap denial of service.
/// This implementation omits the cookie/`mac2` machinery, and this rate limit
/// is what stands in for it.
pub const HANDSHAKE_RATE_LIMIT_MS: u64 = 50;

/// Whether a session established at `established` may still be used at `now`.
pub fn session_is_alive(established: Instant, now: Instant) -> bool {
    now.saturating_since(established) < REJECT_AFTER_TIME_MS
}

/// Whether a passive keepalive is due.
///
/// `armed_since` is the moment data arrived with nothing sent back since. It is
/// deliberately a single piece of state rather than a comparison of "last
/// received" against "last sent": those can carry the same timestamp when a
/// send and a receive land in the same millisecond, and then neither ordering
/// is recoverable. Arming on receipt and disarming on send has no such tie.
pub fn keepalive_is_due(armed_since: Option<Instant>, now: Instant) -> bool {
    armed_since.is_some_and(|armed| now.saturating_since(armed) >= KEEPALIVE_TIMEOUT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire_at_the_reject_boundary() {
        let start = Instant(1_000);
        assert!(session_is_alive(start, Instant(1_000)));
        assert!(session_is_alive(start, Instant(1_000 + REJECT_AFTER_TIME_MS - 1)));
        assert!(!session_is_alive(start, Instant(1_000 + REJECT_AFTER_TIME_MS)));
    }

    #[test]
    fn a_backwards_clock_does_not_expire_a_session() {
        assert!(session_is_alive(Instant(5_000), Instant(1_000)));
    }

    #[test]
    fn keepalive_waits_for_received_data() {
        // Disarmed: nothing to keep alive.
        assert!(!keepalive_is_due(None, Instant(1_000_000)));

        let armed = Instant(1_000);
        assert!(!keepalive_is_due(Some(armed), Instant(1_000)));
        assert!(!keepalive_is_due(
            Some(armed),
            Instant(1_000 + KEEPALIVE_TIMEOUT_MS - 1)
        ));
        assert!(keepalive_is_due(
            Some(armed),
            Instant(1_000 + KEEPALIVE_TIMEOUT_MS)
        ));
    }

    #[test]
    fn a_send_in_the_same_millisecond_still_disarms_the_keepalive() {
        // Disarming is a state change, not a timestamp comparison, so a send
        // that shares a millisecond with the receipt still cancels it.
        assert!(!keepalive_is_due(None, Instant(1_000 + KEEPALIVE_TIMEOUT_MS)));
    }
}
