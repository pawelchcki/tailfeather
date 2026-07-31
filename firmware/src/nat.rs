//! Source NAT for UDP flows leaving the tunnel for the WiFi uplink.
//!
//! This is milestone M3a, scoped to UDP. The plan anticipated that: smoltcp has
//! no forwarding path, so a general implementation needs either raw sockets
//! (where smoltcp is liable to answer forwarded TCP with its own RST) or a
//! `Driver` shim that diverts frames before smoltcp sees them. Neither is
//! needed for UDP.
//!
//! Instead each tunnelled flow gets an ordinary [`embassy_net::udp::UdpSocket`]
//! on the station interface. The stack then builds the outer IP and UDP headers
//! itself, using its own address, which *is* source NAT — and it means no
//! checksum fixup, no raw sockets, and no fighting smoltcp. Replies arrive on
//! the same socket and are rebuilt into inner packets addressed back to the
//! tunnel client.
//!
//! The cost is one socket per concurrent flow, so the table is small and
//! reclaims the least recently used slot under pressure.

use crate::inner::checksum;

/// Concurrent UDP flows. Each costs a socket plus its buffers, so this trades
/// directly against RAM; four is enough to forward DNS and a benchmark at once.
pub const SLOTS: usize = 4;

/// External ports are assigned one per slot, so a reply's destination port
/// identifies its flow before the table is consulted.
pub const EXT_PORT_BASE: u16 = 40000;

/// Drop a flow that has been idle this long, freeing its slot.
pub const IDLE_TIMEOUT_MS: u64 = 30_000;

const PROTO_UDP: u8 = 17;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// The largest inner payload we can forward: a full inner packet less its own
/// IP and UDP headers.
pub const MAX_PAYLOAD: usize = wg_core::budget::INNER_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// One translated flow. The external port is implied by the slot index.
#[derive(Clone, Copy)]
pub struct Flow {
    pub client_ip: [u8; 4],
    pub client_port: u16,
    pub server_ip: [u8; 4],
    pub server_port: u16,
    pub last_used_ms: u64,
}

#[derive(Default)]
pub struct Table {
    flows: [Option<Flow>; SLOTS],
}

impl Table {
    pub const fn new() -> Self {
        Self {
            flows: [None; SLOTS],
        }
    }

    /// The slot for this flow, creating one if necessary.
    ///
    /// Returns the slot index, and whether the caller must rebind that slot's
    /// socket because the slot was reused for a different flow. Returns `None`
    /// only if every slot is occupied by a flow younger than the idle timeout.
    pub fn slot_for(
        &mut self,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) -> Option<usize> {
        let matches = |f: &Flow| {
            f.client_ip == client_ip
                && f.client_port == client_port
                && f.server_ip == server_ip
                && f.server_port == server_port
        };

        if let Some(index) = self
            .flows
            .iter()
            .position(|f| f.is_some_and(|f| matches(&f)))
        {
            if let Some(flow) = &mut self.flows[index] {
                flow.last_used_ms = now_ms;
            }
            return Some(index);
        }

        // Prefer a free slot, then the least recently used one that has gone
        // idle. A busy table never evicts a live flow, it just refuses.
        let victim = self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    f.is_some_and(|f| now_ms.saturating_sub(f.last_used_ms) >= IDLE_TIMEOUT_MS)
                })
                .min_by_key(|(_, f)| f.map(|f| f.last_used_ms).unwrap_or(0))
                .map(|(i, _)| i)
        })?;

        self.flows[victim] = Some(Flow {
            client_ip,
            client_port,
            server_ip,
            server_port,
            last_used_ms: now_ms,
        });
        Some(victim)
    }

    pub fn get(&self, slot: usize) -> Option<Flow> {
        self.flows.get(slot).copied().flatten()
    }

    pub fn touch(&mut self, slot: usize, now_ms: u64) {
        if let Some(Some(flow)) = self.flows.get_mut(slot) {
            flow.last_used_ms = now_ms;
        }
    }
}

/// A parsed inner IPv4/UDP datagram.
pub struct Udp4<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse an inner packet, if it is IPv4 UDP without fragmentation.
///
/// Fragments are rejected rather than reassembled: the tunnel's 1280-byte MTU
/// is small enough that a well-behaved client will not produce them, and
/// reassembly needs buffers this device would rather spend on throughput.
pub fn parse_udp4(packet: &[u8]) -> Option<Udp4<'_>> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != PROTO_UDP {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    // The fragment-offset field and the "more fragments" bit must both be zero.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }

    let udp = packet.get(header_len..)?;
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if !(UDP_HEADER_LEN..=udp.len()).contains(&length) {
        return None;
    }

    Some(Udp4 {
        src_ip: packet[12..16].try_into().ok()?,
        dst_ip: packet[16..20].try_into().ok()?,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..length],
    })
}

/// Build an inner IPv4/UDP datagram into `out`, returning its length.
pub fn build_udp4(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let out = out.get_mut(..total)?;

    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // A zero identification field is fine precisely because we never fragment.
    out[4..6].fill(0);
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    out[8] = 64;
    out[9] = PROTO_UDP;
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&src_ip);
    out[16..20].copy_from_slice(&dst_ip);
    let ip_checksum = checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let udp = &mut out[IPV4_HEADER_LEN..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].fill(0);
    udp[UDP_HEADER_LEN..].copy_from_slice(payload);

    // UDP's checksum covers a pseudo-header of the IP addresses, protocol and
    // length as well as the datagram itself.
    let pseudo = pseudo_header_sum(src_ip, dst_ip, udp_len);
    let sum = checksum_with_carry(udp, pseudo);
    // All-zero means "no checksum" in IPv4, so a genuine zero is sent as ~0.
    let sum = if sum == 0 { 0xffff } else { sum };
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&sum.to_be_bytes());

    Some(total)
}

fn pseudo_header_sum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_len: u16) -> u32 {
    let mut sum = 0u32;
    for pair in src_ip.chunks_exact(2).chain(dst_ip.chunks_exact(2)) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    sum + PROTO_UDP as u32 + udp_len as u32
}

/// The internet checksum of `bytes`, folded together with an existing partial
/// sum such as a pseudo-header.
fn checksum_with_carry(bytes: &[u8], mut sum: u32) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
