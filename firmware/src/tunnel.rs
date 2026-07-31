//! The WireGuard data path: a UDP socket on one side, [`wg_core::Device`] on
//! the other, and source NAT out of the WiFi uplink for anything the tunnel
//! wants to forward.
//!
//! Everything runs in one task. The cryptography is the bottleneck by a wide
//! margin, so there is nothing to gain from processing packets concurrently,
//! and a single task means [`wg_core::Device`] needs no locking.

use embassy_futures::select::{Either4, select4, select_array};
use embassy_net::raw::{IpProtocol, IpVersion, RawSocket};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpEndpoint, Ipv4Address, Stack, raw, udp};
use embassy_time::{Duration, Timer};
use log::{info, warn};
use static_cell::StaticCell;
use wg_core::{Action, Device, Instant, PeerId, Rng};

use crate::nat;

/// The port we listen on, and the one the peer's `Endpoint` must point at.
const LISTEN_PORT: u16 = 51820;

/// How long to idle before giving the timers a turn. Keepalives are due on a
/// ten-second scale, so a quarter second is ample resolution.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Point-to-point for now: one upstream peer, so one slot.
const PEERS: usize = 1;

/// Enough for a handful of full-size datagrams to queue while the tunnel is
/// busy with the ChaCha20 work of the previous one.
const WG_BUFFER_LEN: usize = 8 * wg_core::MAX_DATAGRAM_LEN;
const WG_PACKETS: usize = 16;

/// Per-NAT-socket buffering. Smaller than the tunnel's, because a forwarded
/// flow is rate-limited by the tunnel anyway.
const NAT_BUFFER_LEN: usize = 4 * 1024;
const NAT_PACKETS: usize = 8;

static WG_RX_META: StaticCell<[PacketMetadata; WG_PACKETS]> = StaticCell::new();
static WG_TX_META: StaticCell<[PacketMetadata; WG_PACKETS]> = StaticCell::new();
static WG_RX_BUFFER: StaticCell<[u8; WG_BUFFER_LEN]> = StaticCell::new();
static WG_TX_BUFFER: StaticCell<[u8; WG_BUFFER_LEN]> = StaticCell::new();

/// The shared raw socket carrying every translated TCP flow. Sized for a
/// handful of full-size segments in flight.
const RAW_BUFFER_LEN: usize = 8 * 1024;
const RAW_PACKETS: usize = 16;

static RAW_RX_META: StaticCell<[raw::PacketMetadata; RAW_PACKETS]> = StaticCell::new();
static RAW_TX_META: StaticCell<[raw::PacketMetadata; RAW_PACKETS]> = StaticCell::new();
static RAW_RX_BUFFER: StaticCell<[u8; RAW_BUFFER_LEN]> = StaticCell::new();
static RAW_TX_BUFFER: StaticCell<[u8; RAW_BUFFER_LEN]> = StaticCell::new();

static NAT_RX_META: StaticCell<[[PacketMetadata; NAT_PACKETS]; nat::SLOTS]> = StaticCell::new();
static NAT_TX_META: StaticCell<[[PacketMetadata; NAT_PACKETS]; nat::SLOTS]> = StaticCell::new();
static NAT_RX_BUFFER: StaticCell<[[u8; NAT_BUFFER_LEN]; nat::SLOTS]> = StaticCell::new();
static NAT_TX_BUFFER: StaticCell<[[u8; NAT_BUFFER_LEN]; nat::SLOTS]> = StaticCell::new();

static DEVICE: StaticCell<Device<PEERS>> = StaticCell::new();
static SCRATCH: StaticCell<Scratch> = StaticCell::new();

/// The working buffers, kept out of the task's future so the executor's task
/// arena does not have to carry several kilobytes of stack.
struct Scratch {
    /// A received outer datagram, or a received NAT reply payload.
    datagram: [u8; 2048],
    /// Whatever `wg-core` is about to emit.
    out: [u8; wg_core::MAX_DATAGRAM_LEN],
    /// An inner packet we have built and are about to encapsulate.
    inner: [u8; wg_core::budget::INNER_MTU],
}

/// The hardware RNG, which yields true random numbers here because the radio is
/// running and mixes physical noise into it. `Trng` would additionally occupy
/// the ADC, which buys nothing while WiFi is up.
struct HwRng(esp_hal::rng::Rng);

impl Rng for HwRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

fn now() -> Instant {
    Instant(embassy_time::Instant::now().as_millis())
}

#[embassy_executor::task]
pub async fn tunnel(stack: Stack<'static>) -> ! {
    let device = DEVICE.init(Device::new(crate::WG_PRIVATE_KEY));
    // The peer an action applies to always comes back from `handle_udp`, so
    // registration's return value is of no use here.
    device
        .add_peer(crate::WG_PEER_PUBLIC_KEY, None)
        .expect("the peer table has room for the one configured peer");
    let mut rng = HwRng(esp_hal::rng::Rng::new());
    let scratch = SCRATCH.init(Scratch {
        datagram: [0; 2048],
        out: [0; wg_core::MAX_DATAGRAM_LEN],
        inner: [0; wg_core::budget::INNER_MTU],
    });

    let mut wg_socket = UdpSocket::new(
        stack,
        WG_RX_META.init([PacketMetadata::EMPTY; WG_PACKETS]),
        WG_RX_BUFFER.init([0; WG_BUFFER_LEN]),
        WG_TX_META.init([PacketMetadata::EMPTY; WG_PACKETS]),
        WG_TX_BUFFER.init([0; WG_BUFFER_LEN]),
    );
    wg_socket.bind(LISTEN_PORT).expect("port 51820 is free");

    let mut rx_meta = NAT_RX_META.init([[PacketMetadata::EMPTY; NAT_PACKETS]; nat::SLOTS]).iter_mut();
    let mut tx_meta = NAT_TX_META.init([[PacketMetadata::EMPTY; NAT_PACKETS]; nat::SLOTS]).iter_mut();
    let mut rx_buffer = NAT_RX_BUFFER.init([[0; NAT_BUFFER_LEN]; nat::SLOTS]).iter_mut();
    let mut tx_buffer = NAT_TX_BUFFER.init([[0; NAT_BUFFER_LEN]; nat::SLOTS]).iter_mut();
    let mut nat_sockets: [UdpSocket; nat::SLOTS] = core::array::from_fn(|slot| {
        let mut socket = UdpSocket::new(
            stack,
            rx_meta.next().expect("one metadata block per slot"),
            rx_buffer.next().expect("one receive buffer per slot"),
            tx_meta.next().expect("one metadata block per slot"),
            tx_buffer.next().expect("one send buffer per slot"),
        );
        socket
            .bind(nat::EXT_PORT_BASE + slot as u16)
            .expect("external ports are unused");
        socket
    });
    let mut table = nat::Table::new();

    // One raw socket handles all TCP. Unlike UDP, a forwarded connection
    // cannot use a `TcpSocket`, because that would terminate the connection
    // here rather than pass it through.
    let raw_socket = RawSocket::new(
        stack,
        Some(IpVersion::Ipv4),
        Some(IpProtocol::Tcp),
        RAW_RX_META.init([raw::PacketMetadata::EMPTY; RAW_PACKETS]),
        RAW_RX_BUFFER.init([0; RAW_BUFFER_LEN]),
        RAW_TX_META.init([raw::PacketMetadata::EMPTY; RAW_PACKETS]),
        RAW_TX_BUFFER.init([0; RAW_BUFFER_LEN]),
    );
    let mut tcp_table = nat::TcpTable::new();

    // Translated packets must carry this device's own address as their source.
    let our_ip = stack
        .config_v4()
        .expect("the tunnel task starts only after DHCP has completed")
        .address
        .address()
        .octets();

    info!("wireguard listening on :{LISTEN_PORT}, {} NAT slots", nat::SLOTS);

    // We never initiate, so the peer's address is only ever learned from the
    // traffic it sends, and it may change as its NAT mapping does.
    let mut endpoint = None;

    loop {
        // `wait_recv_ready` borrows immutably, so all the sockets can be waited
        // on together and only the one that fired is then borrowed mutably.
        let ready = {
            let wg_ready = wg_socket.wait_recv_ready();
            let nat_ready = select_array(core::array::from_fn::<_, { nat::SLOTS }, _>(|i| {
                nat_sockets[i].wait_recv_ready()
            }));
            match select4(
                wg_ready,
                nat_ready,
                raw_socket.wait_recv_ready(),
                Timer::after(POLL_INTERVAL),
            )
            .await
            {
                Either4::First(()) => Ready::Tunnel,
                Either4::Second(((), slot)) => Ready::Nat(slot),
                Either4::Third(()) => Ready::Raw,
                Either4::Fourth(()) => Ready::Timers,
            }
        };

        match ready {
            Ready::Tunnel => {
                if let Ok((len, from)) = wg_socket.recv_from(&mut scratch.datagram).await {
                    endpoint = Some(from);
                    handle_tunnel_datagram(
                        device,
                        &mut rng,
                        scratch,
                        len,
                        from,
                        &wg_socket,
                        &mut nat_sockets,
                        &mut table,
                        &raw_socket,
                        &mut tcp_table,
                        our_ip,
                    )
                    .await;
                }
            }
            Ready::Nat(slot) => {
                handle_nat_reply(
                    device,
                    scratch,
                    slot,
                    &nat_sockets[slot],
                    &mut table,
                    &wg_socket,
                    endpoint,
                )
                .await;
            }
            Ready::Raw => {
                handle_raw_reply(
                    device,
                    scratch,
                    &raw_socket,
                    &mut tcp_table,
                    &wg_socket,
                    endpoint,
                )
                .await;
            }
            Ready::Timers => {}
        }

        while let Action::Send { data, .. } = device.poll_timers(now(), &mut scratch.out) {
            let Some(to) = endpoint else { break };
            send(&wg_socket, data, to).await;
        }
    }
}

enum Ready {
    Tunnel,
    Nat(usize),
    Raw,
    Timers,
}

/// Decrypt one outer datagram and act on whatever was inside it.
#[allow(clippy::too_many_arguments)]
async fn handle_tunnel_datagram(
    device: &mut Device<PEERS>,
    rng: &mut HwRng,
    scratch: &mut Scratch,
    len: usize,
    from: udp::UdpMetadata,
    wg_socket: &UdpSocket<'_>,
    nat_sockets: &mut [UdpSocket<'_>; nat::SLOTS],
    table: &mut nat::Table,
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    our_ip: [u8; 4],
) {
    let Scratch {
        datagram,
        out,
        inner,
    } = scratch;

    match device.handle_udp(&datagram[..len], now(), rng, out) {
        Ok(Action::Send { data, .. }) => send(wg_socket, data, from).await,
        Ok(Action::Receive { peer, packet }) => {
            // An echo request for our own tunnel address is answered here;
            // anything else is forwarded.
            if let Some(reply_len) = crate::inner::icmp_echo_reply(packet, crate::WG_TUNNEL_IP, inner)
            {
                encapsulate_and_send(device, peer, &inner[..reply_len], out, wg_socket, from).await;
            } else if let Some(flow) = nat::parse_udp4(packet) {
                forward_out(nat_sockets, table, &flow).await;
            } else if let Some(info) = nat::parse_tcp4(packet) {
                forward_tcp_out(raw_socket, tcp_table, inner, packet, &info, our_ip).await;
            }
        }
        Ok(Action::None) => {}
        Err(e) => warn!("rx: {e}"),
    }
}

/// Send a tunnelled UDP payload out of the uplink, from the station's own
/// address.
async fn forward_out(
    nat_sockets: &mut [UdpSocket<'_>; nat::SLOTS],
    table: &mut nat::Table,
    flow: &nat::Udp4<'_>,
) {
    if flow.payload.len() > nat::MAX_PAYLOAD {
        return;
    }
    let Some(slot) = table.slot_for(
        flow.src_ip,
        flow.src_port,
        flow.dst_ip,
        flow.dst_port,
        embassy_time::Instant::now().as_millis(),
    ) else {
        // Every slot is busy with a live flow. Dropping is the honest response;
        // UDP callers are expected to cope with loss.
        return;
    };

    let destination = IpEndpoint::new(Ipv4Address::from(flow.dst_ip).into(), flow.dst_port);
    if let Err(e) = nat_sockets[slot].send_to(flow.payload, destination).await {
        warn!("nat send: {e:?}");
    }
}

/// Translate a TCP segment from the tunnel and put it on the uplink.
///
/// Unlike UDP, nothing here terminates the connection: the segment keeps its
/// sequence numbers, flags and payload, and only its source address and port
/// are rewritten. The connection is between the tunnel client and the server,
/// with this device in the middle.
async fn forward_tcp_out(
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    scratch: &mut [u8],
    packet: &[u8],
    info: &nat::TcpInfo,
    our_ip: [u8; 4],
) {
    let now_ms = embassy_time::Instant::now().as_millis();
    let Some(slot) = tcp_table.slot_for(
        info.src_ip,
        info.src_port,
        info.dst_ip,
        info.dst_port,
        now_ms,
    ) else {
        return;
    };

    let Some(buffer) = scratch.get_mut(..packet.len()) else {
        return;
    };
    buffer.copy_from_slice(packet);

    // Clamp before translating: the option is covered by the checksum, and
    // both adjustments are incremental from whatever it currently is.
    nat::clamp_mss(buffer);
    if !nat::rewrite_tcp_outbound(buffer, our_ip, nat::TCP_EXT_PORT_BASE + slot as u16) {
        return;
    }

    raw_socket.send(buffer).await;
    if info.is_rst {
        tcp_table.release(slot);
    }
}

/// Translate a TCP segment arriving from the uplink back into the tunnel.
async fn handle_raw_reply(
    device: &mut Device<PEERS>,
    scratch: &mut Scratch,
    raw_socket: &RawSocket<'_>,
    tcp_table: &mut nat::TcpTable,
    wg_socket: &UdpSocket<'_>,
    endpoint: Option<udp::UdpMetadata>,
) {
    let Scratch { out, inner, .. } = scratch;

    let Ok(len) = raw_socket.recv(inner).await else {
        return;
    };
    let packet = &inner[..len];
    let Some(info) = nat::parse_tcp4(packet) else {
        return;
    };

    // The raw socket sees every inbound segment, including any that belong to
    // this device's own connections rather than to a forwarded flow. The
    // destination port is what tells them apart.
    let Some(slot) = info
        .dst_port
        .checked_sub(nat::TCP_EXT_PORT_BASE)
        .map(usize::from)
        .filter(|slot| *slot < nat::TCP_SLOTS)
    else {
        return;
    };
    let Some(flow) = tcp_table.get(slot) else {
        return;
    };
    let Some(to) = endpoint else { return };
    let is_rst = info.is_rst;
    tcp_table.touch(slot, embassy_time::Instant::now().as_millis());

    let inner_packet = &mut inner[..len];
    nat::clamp_mss(inner_packet);
    if !nat::rewrite_tcp_inbound(inner_packet, flow.client_ip, flow.client_port) {
        return;
    }

    match device.encapsulate(PeerId(0), &inner[..len], now(), out) {
        Ok(Action::Send { data, .. }) => send(wg_socket, data, to).await,
        Ok(_) => {}
        Err(e) => warn!("encapsulate: {e}"),
    }

    if is_rst {
        tcp_table.release(slot);
    }
}

/// Take a reply that arrived on a NAT socket and put it back into the tunnel.
///
/// `endpoint` is where the peer was last heard from. A reply can only arrive
/// after the peer sent something, so in practice it is always known by now.
#[allow(clippy::too_many_arguments)]
async fn handle_nat_reply(
    device: &mut Device<PEERS>,
    scratch: &mut Scratch,
    slot: usize,
    socket: &UdpSocket<'_>,
    table: &mut nat::Table,
    wg_socket: &UdpSocket<'_>,
    endpoint: Option<udp::UdpMetadata>,
) {
    let Scratch {
        datagram,
        out,
        inner,
    } = scratch;

    let Ok((len, _)) = socket.recv_from(datagram).await else {
        return;
    };
    let Some(flow) = table.get(slot) else { return };
    let Some(to) = endpoint else { return };
    table.touch(slot, embassy_time::Instant::now().as_millis());

    // The client addressed the server, so the reply must appear to come from
    // the server, not from this gateway. That is what makes the translation
    // invisible to the client.
    let Some(inner_len) = nat::build_udp4(
        flow.server_ip,
        flow.server_port,
        flow.client_ip,
        flow.client_port,
        &datagram[..len],
        inner,
    ) else {
        return;
    };

    // There is exactly one configured peer, and a NAT reply belongs to whoever
    // opened the flow, so it can only be that one.
    encapsulate_and_send(device, PeerId(0), &inner[..inner_len], out, wg_socket, to).await;
}

async fn encapsulate_and_send(
    device: &mut Device<PEERS>,
    peer: PeerId,
    packet: &[u8],
    out: &mut [u8],
    socket: &UdpSocket<'_>,
    to: udp::UdpMetadata,
) {
    match device.encapsulate(peer, packet, now(), out) {
        Ok(Action::Send { data, .. }) => send(socket, data, to).await,
        Ok(_) => {}
        Err(e) => warn!("encapsulate: {e}"),
    }
}

async fn send(socket: &UdpSocket<'_>, data: &[u8], to: udp::UdpMetadata) {
    if let Err(e) = socket.send_to(data, to).await {
        warn!("send: {e:?}");
    }
}
