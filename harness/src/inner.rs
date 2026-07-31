//! Answers ICMP echo requests that arrive inside the tunnel.
//!
//! Milestone M2 is verified by pinging the tunnel address, so something has to
//! reply. This is deliberately the narrowest possible responder: it handles
//! echo requests addressed to us and ignores everything else. Real forwarding
//! is M3's job.

const PROTO_ICMP: u8 = 1;
const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;

/// The internet checksum of RFC 1071: the one's complement of the one's
/// complement sum of the data taken as 16-bit big-endian words.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // An odd trailing byte is padded on the right, not the left.
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Turn an ICMP echo request addressed to `our_ip` into an echo reply written
/// to `out`, returning its length.
///
/// Returns `None` if `packet` is not an echo request for us.
pub fn icmp_echo_reply(packet: &[u8], our_ip: [u8; 4], out: &mut [u8]) -> Option<usize> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if packet[9] != PROTO_ICMP || packet.len() < header_len + 8 {
        return None;
    }
    if packet[16..20] != our_ip || packet[header_len] != ECHO_REQUEST {
        return None;
    }

    let out = out.get_mut(..packet.len())?;
    out.copy_from_slice(packet);

    // Swap source and destination so the reply returns to the sender.
    out.copy_within(12..16, 16);
    out[12..16].copy_from_slice(&packet[16..20]);
    out[8] = 64;
    out[10..12].fill(0);
    let ip_checksum = checksum(&out[..header_len]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // A reply differs from a request only in the type byte, so the identifier,
    // sequence number and payload are carried over untouched — which is what
    // lets `ping` match the reply to its request.
    out[header_len] = ECHO_REPLY;
    out[header_len + 2..header_len + 4].fill(0);
    let icmp_checksum = checksum(&out[header_len..]);
    out[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    Some(out.len())
}
