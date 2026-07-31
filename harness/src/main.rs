//! Runs the project's library crates on the development machine, with no
//! hardware and no operating system underneath them.
//!
//! This targets `x86_64-unknown-linux-none`: the Linux syscall ABI, but no
//! libc, no `std`, and no allocator. That combination is the point. The
//! firmware's library crates are `no_std` and allocation-free, and the only way
//! to be confident they *stay* that way — and that they behave identically off
//! the chip — is to run them somewhere just as bare. A `std` test binary would
//! hide an accidental dependence on the hosted environment; this does not.
//!
//! Today it drives `wg-core` against a real `wg-quick` peer, proving milestone
//! M2 without an ESP32 in hand. As `ts-control` and `micro-h2` arrive it will
//! grow an async executor and register against a local Headscale.
//!
//! ```text
//! harness <bind ip> <port> <our private key hex> <peer public key hex> <our tunnel ipv4>
//! ```

#![no_std]
#![no_main]

mod inner;
mod rt;

use wg_core::{Action, Device, Instant, Rng};

/// The kernel's entropy pool, via `getrandom`.
struct OsRng;

impl Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut filled = 0;
        while filled < dest.len() {
            match rt::getrandom(&mut dest[filled..]) {
                Ok(0) | Err(_) => panic!("getrandom failed"),
                Ok(n) => filled += n,
            }
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {}", info.message());
    rt::exit(101)
}

/// The process entry point.
///
/// The kernel enters `_start` with `rsp` pointing at `argc`, and with no
/// guarantee of the 16-byte stack alignment the C ABI requires. A naked
/// function is the only way to capture that pointer and fix the alignment
/// before calling anything compiled normally.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {main}",
        main = sym rust_start,
    )
}

/// Arguments as the kernel lays them out: `argc`, then `argc` pointers to
/// NUL-terminated strings.
struct Args {
    stack: *const usize,
}

impl Args {
    fn count(&self) -> usize {
        unsafe { *self.stack }
    }

    fn get(&self, index: usize) -> Option<&'static str> {
        if index >= self.count() {
            return None;
        }
        unsafe {
            let ptr = *self.stack.add(1 + index) as *const u8;
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(ptr, len)).ok()
        }
    }
}

extern "C" fn rust_start(stack: *const usize) -> ! {
    let args = Args { stack };
    let (Some(bind_ip), Some(port), Some(private_hex), Some(peer_hex), Some(tunnel_ip)) = (
        args.get(1),
        args.get(2),
        args.get(3),
        args.get(4),
        args.get(5),
    ) else {
        println!(
            "usage: harness <bind ip> <port> <private key hex> <peer public key hex> <tunnel ipv4>"
        );
        rt::exit(2)
    };

    let bind_ip = parse_ipv4(bind_ip).expect("bind address must be IPv4");
    let port = parse_u16(port).expect("port must be a number");
    let tunnel_ip = parse_ipv4(tunnel_ip).expect("tunnel address must be IPv4");

    let mut device: Device<1> = Device::new(parse_key(private_hex));
    let peer = device
        .add_peer(parse_key(peer_hex), None)
        .expect("the peer table has room for one peer");

    println!("our public key: {}", HexBytes(&device.public_key()));

    let socket = rt::socket_udp().expect("socket");
    rt::bind(socket, &rt::SockAddrIn::new(bind_ip, port)).expect("bind");

    let started = rt::monotonic_millis();
    let mut datagram = [0u8; 2048];
    let mut out = [0u8; wg_core::MAX_DATAGRAM_LEN];
    let mut reply = [0u8; wg_core::MAX_DATAGRAM_LEN];
    let mut endpoint: Option<rt::SockAddrIn> = None;

    println!("listening on {}.{}.{}.{}:{}", bind_ip[0], bind_ip[1], bind_ip[2], bind_ip[3], port);

    loop {
        let now = || Instant(rt::monotonic_millis() - started);

        if rt::poll_readable(socket, 250).unwrap_or(false)
            && let Ok((len, from)) = rt::recv_from(socket, &mut datagram)
        {
            endpoint = Some(from);
            match device.handle_udp(&datagram[..len], now(), &mut OsRng, &mut out) {
                Ok(Action::Send { data, .. }) => {
                    println!("-> handshake response, {} bytes", data.len());
                    let _ = rt::send_to(socket, data, &from);
                }
                Ok(Action::Receive { packet, .. }) => {
                    println!("<- tunnelled packet, {} bytes", packet.len());
                    if let Some(n) = inner::icmp_echo_reply(packet, tunnel_ip, &mut reply) {
                        let mut sealed = [0u8; wg_core::MAX_DATAGRAM_LEN];
                        match device.encapsulate(peer, &reply[..n], now(), &mut sealed) {
                            Ok(Action::Send { data, .. }) => {
                                println!("-> echo reply, {} bytes", data.len());
                                let _ = rt::send_to(socket, data, &from);
                            }
                            Ok(_) => {}
                            Err(e) => println!("!! encapsulate: {}", e),
                        }
                    }
                }
                Ok(Action::None) => {}
                Err(e) => println!("!! {}", e),
            }
        }

        while let Action::Send { data, .. } = device.poll_timers(now(), &mut out) {
            let Some(to) = endpoint else { break };
            println!("-> keepalive, {} bytes", data.len());
            let _ = rt::send_to(socket, data, &to);
        }
    }
}

/// Formats bytes as lowercase hex without allocating.
struct HexBytes<'a>(&'a [u8]);

impl core::fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn parse_key(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "a key must be 64 hex characters");
    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        *slot = nibble(bytes[i * 2]) << 4 | nibble(bytes[i * 2 + 1]);
    }
    key
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

fn parse_u16(s: &str) -> Option<u16> {
    let mut value: u32 = 0;
    if s.is_empty() {
        return None;
    }
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (c - b'0') as u32;
        if value > u16::MAX as u32 {
            return None;
        }
    }
    Some(value as u16)
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in octets.iter_mut() {
        let part = parts.next()?;
        *slot = u8::try_from(parse_u16(part)?).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}
