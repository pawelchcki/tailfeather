//! The WireGuard data path: a UDP socket on one side, [`wg_core::Device`] on
//! the other.
//!
//! This mirrors `wg-core`'s `responder` example, which drives the identical
//! sans-io API over `std::net::UdpSocket`. Only the socket and the clock differ.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Stack, udp};
use embassy_time::{Duration, with_timeout};
use log::{info, warn};
use static_cell::StaticCell;
use wg_core::{Action, Device, Instant, PeerId, Rng};

/// The port we listen on, and the one the peer's `Endpoint` must point at.
const LISTEN_PORT: u16 = 51820;

/// How long to block on a receive before giving the timers a turn. Keepalives
/// are due on a ten-second scale, so a quarter second is ample resolution.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Point-to-point for now: one upstream peer, so one slot.
const PEERS: usize = 1;

/// Enough for a handful of full-size datagrams to queue up while the tunnel is
/// busy with the ChaCha20 work of the previous one.
const SOCKET_BUFFER_LEN: usize = 4 * wg_core::MAX_DATAGRAM_LEN;
const SOCKET_PACKETS: usize = 8;

static RX_META: StaticCell<[PacketMetadata; SOCKET_PACKETS]> = StaticCell::new();
static TX_META: StaticCell<[PacketMetadata; SOCKET_PACKETS]> = StaticCell::new();
static RX_BUFFER: StaticCell<[u8; SOCKET_BUFFER_LEN]> = StaticCell::new();
static TX_BUFFER: StaticCell<[u8; SOCKET_BUFFER_LEN]> = StaticCell::new();
static DEVICE: StaticCell<Device<PEERS>> = StaticCell::new();
static SCRATCH: StaticCell<Scratch> = StaticCell::new();

/// The three working buffers, kept out of the task's future so that the
/// executor's task arena does not have to carry four kilobytes of stack.
struct Scratch {
    datagram: [u8; wg_core::MAX_DATAGRAM_LEN],
    out: [u8; wg_core::MAX_DATAGRAM_LEN],
    reply: [u8; wg_core::MAX_DATAGRAM_LEN],
}

/// The hardware RNG, which yields true random numbers here because the radio is
/// running and mixes physical noise into it. `Trng` would additionally occupy
/// the ADC, which buys nothing while Wi-Fi is up.
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
    // The id of the peer we act on always comes back from `handle_udp`, so
    // registration's return value is of no use here.
    device
        .add_peer(crate::WG_PEER_PUBLIC_KEY, None)
        .expect("the peer table has room for the one configured peer");
    let mut rng = HwRng(esp_hal::rng::Rng::new());
    let scratch = SCRATCH.init(Scratch {
        datagram: [0; wg_core::MAX_DATAGRAM_LEN],
        out: [0; wg_core::MAX_DATAGRAM_LEN],
        reply: [0; wg_core::MAX_DATAGRAM_LEN],
    });

    let mut socket = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; SOCKET_PACKETS]),
        RX_BUFFER.init([0; SOCKET_BUFFER_LEN]),
        TX_META.init([PacketMetadata::EMPTY; SOCKET_PACKETS]),
        TX_BUFFER.init([0; SOCKET_BUFFER_LEN]),
    );
    socket.bind(LISTEN_PORT).expect("port 51820 is free");
    info!("wireguard listening on :{LISTEN_PORT}");

    // We never initiate, so the peer's address is only ever learned from the
    // traffic it sends, and it may change as its NAT mapping does.
    let mut endpoint = None;

    loop {
        match with_timeout(POLL_INTERVAL, socket.recv_from(&mut scratch.datagram)).await {
            Ok(Ok((len, from))) => {
                endpoint = Some(from);
                match device.handle_udp(&scratch.datagram[..len], now(), &mut rng, &mut scratch.out)
                {
                    Ok(Action::Send { data, .. }) => {
                        send(&socket, data, from).await;
                    }
                    Ok(Action::Receive { peer, packet }) => {
                        if let Some(len) =
                            crate::inner::icmp_echo_reply(packet, crate::WG_TUNNEL_IP, &mut scratch.reply)
                        {
                            encapsulate(device, peer, len, scratch, &socket, from).await;
                        }
                    }
                    Ok(Action::None) => {}
                    Err(e) => warn!("rx: {e}"),
                }
            }
            Ok(Err(e)) => warn!("recv: {e:?}"),
            // A timeout is the normal idle path, and the point at which timers
            // get a chance to run.
            Err(_) => {}
        }

        while let Action::Send { data, .. } = device.poll_timers(now(), &mut scratch.out) {
            let Some(to) = endpoint else { break };
            send(&socket, data, to).await;
        }
    }
}

/// Encapsulating borrows `scratch.out` mutably while the reply is read out of
/// `scratch.reply`, which the borrow checker only accepts once the two fields
/// are split apart.
async fn encapsulate(
    device: &mut Device<PEERS>,
    peer: PeerId,
    reply_len: usize,
    scratch: &mut Scratch,
    socket: &UdpSocket<'_>,
    to: udp::UdpMetadata,
) {
    let Scratch { out, reply, .. } = scratch;
    match device.encapsulate(peer, &reply[..reply_len], now(), out) {
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
