//! Async sockets over the reactor.
//!
//! Deliberately thin. Every one of these is the same three steps: try the
//! syscall, and if it reports `EAGAIN`, await readiness and try again. `rustix`
//! owns the descriptors, so closing is a `Drop` we do not have to write, and
//! addresses are `core::net` types rather than a hand-rolled `sockaddr_in`.

use core::net::{Ipv4Addr, SocketAddrV4};

use rustix::event::PollFlags;
use rustix::fd::{AsRawFd, OwnedFd, RawFd};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, accept_with, bind, connect,
    getsockname, listen, recvfrom, sendto, socket_with, sockopt,
};

use crate::exec::Reactor;

/// Why a socket operation failed, distinguishing the cases a caller can do
/// something about from the ones it cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    Errno(Errno),
    /// The peer closed the connection.
    Closed,
    /// A datagram arrived from something that is not an IPv4 address, which
    /// this node has no way to reply to.
    NotIpv4,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Errno(e) => write!(f, "errno {}", e.raw_os_error()),
            Self::Closed => f.write_str("connection closed"),
            Self::NotIpv4 => f.write_str("peer is not IPv4"),
        }
    }
}

/// Whether an error means "not ready yet" rather than "failed".
fn would_block(e: Errno) -> bool {
    e == Errno::AGAIN || e == Errno::WOULDBLOCK || e == Errno::INTR
}

fn new_socket(kind: SocketType) -> Result<OwnedFd, NetError> {
    socket_with(
        AddressFamily::INET,
        kind,
        // Always non-blocking: one blocking call would stall the whole
        // single-threaded executor, and everything above expects to be able to
        // wait on several things at once.
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .map_err(NetError::Errno)
}

fn local_v4(fd: &OwnedFd) -> Result<SocketAddrV4, NetError> {
    getsockname(fd)
        .map_err(NetError::Errno)?
        .try_into()
        .map_err(|_| NetError::NotIpv4)
}

pub struct UdpSocket<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> UdpSocket<'r> {
    pub fn bind(reactor: &'r Reactor, address: Ipv4Addr, port: u16) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::DGRAM)?;
        bind(&fd, &SocketAddrV4::new(address, port)).map_err(NetError::Errno)?;
        Ok(Self { fd, reactor })
    }

    /// The address actually bound, which answers what port the kernel chose
    /// when the caller asked for zero.
    pub fn local_address(&self) -> Result<SocketAddrV4, NetError> {
        local_v4(&self.fd)
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), NetError> {
        loop {
            match recvfrom(&self.fd, &mut *buf, RecvFlags::empty()) {
                Ok((len, _truncated, Some(from))) => {
                    let from = from.try_into().map_err(|_| NetError::NotIpv4)?;
                    return Ok((len, from));
                }
                // A datagram socket that has been `connect`ed reports no
                // address. This one never is, so this cannot happen — but
                // guessing an address would be worse than saying so.
                Ok((_, _, None)) => return Err(NetError::NotIpv4),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    /// Send one datagram.
    ///
    /// A datagram is sent whole or not at all, so unlike a stream there is no
    /// partial-write case to loop over — only the "no buffer space" retry.
    pub async fn send_to(&self, buf: &[u8], to: &SocketAddrV4) -> Result<usize, NetError> {
        loop {
            match sendto(&self.fd, buf, SendFlags::empty(), to) {
                Ok(n) => return Ok(n),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::OUT).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }
}

/// A listening socket. Exists so the self-test can prove [`TcpStream`] against
/// the kernel's own TCP rather than against a mock; a node never listens.
pub struct TcpListener<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> TcpListener<'r> {
    pub fn bind(reactor: &'r Reactor, address: Ipv4Addr, port: u16) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::STREAM)?;
        bind(&fd, &SocketAddrV4::new(address, port)).map_err(NetError::Errno)?;
        listen(&fd, 1).map_err(NetError::Errno)?;
        Ok(Self { fd, reactor })
    }

    pub fn local_address(&self) -> Result<SocketAddrV4, NetError> {
        local_v4(&self.fd)
    }

    pub async fn accept(&self) -> Result<TcpStream<'r>, NetError> {
        loop {
            // The accepted descriptor inherits non-blocking mode atomically;
            // setting it afterwards would leave a window in which a read blocks.
            match accept_with(&self.fd, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC) {
                Ok(fd) => {
                    return Ok(TcpStream {
                        fd,
                        reactor: self.reactor,
                    });
                }
                Err(e) if would_block(e) => {
                    self.reactor
                        .ready(self.fd.as_raw_fd(), PollFlags::IN)
                        .await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }
}

pub struct TcpStream<'r> {
    fd: OwnedFd,
    reactor: &'r Reactor,
}

impl<'r> TcpStream<'r> {
    /// Connect, without blocking the executor while the handshake completes.
    ///
    /// A non-blocking `connect` returns `EINPROGRESS` and finishes later; the
    /// socket becoming writable only means the attempt *concluded*, so
    /// `SO_ERROR` must be read to find out whether it concluded successfully.
    /// Skipping that check is the classic way to get a "connected" socket that
    /// fails on first write with a connection refused from minutes earlier.
    pub async fn connect(
        reactor: &'r Reactor,
        address: Ipv4Addr,
        port: u16,
    ) -> Result<Self, NetError> {
        let fd = new_socket(SocketType::STREAM)?;
        match connect(&fd, &SocketAddrV4::new(address, port)) {
            Ok(()) => {}
            Err(Errno::INPROGRESS) => {
                reactor.ready(fd.as_raw_fd(), PollFlags::OUT).await;
                match sockopt::socket_error(&fd).map_err(NetError::Errno)? {
                    Ok(()) => {}
                    Err(e) => return Err(NetError::Errno(e)),
                }
            }
            Err(e) => return Err(NetError::Errno(e)),
        }
        Ok(Self { fd, reactor })
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Read into `buf`, returning how many bytes arrived.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        loop {
            match rustix::io::read(&self.fd, &mut *buf) {
                Ok(0) => return Err(NetError::Closed),
                Ok(n) => return Ok(n),
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::IN).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
    }

    /// Read exactly `buf.len()` bytes, or fail.
    ///
    /// Every framed protocol above this — controlbase records, HTTP/2 frames —
    /// needs this rather than `read`, because a short read is the normal case on
    /// a stream and treating it as a complete message is how framing bugs start.
    pub async fn read_exact(&self, buf: &mut [u8]) -> Result<(), NetError> {
        let mut filled = 0;
        while filled < buf.len() {
            filled += self.read(&mut buf[filled..]).await?;
        }
        Ok(())
    }

    pub async fn write_all(&self, buf: &[u8]) -> Result<(), NetError> {
        let mut written = 0;
        while written < buf.len() {
            match rustix::io::write(&self.fd, &buf[written..]) {
                Ok(0) => return Err(NetError::Closed),
                Ok(n) => written += n,
                Err(e) if would_block(e) => {
                    self.reactor.ready(self.raw(), PollFlags::OUT).await;
                }
                Err(e) => return Err(NetError::Errno(e)),
            }
        }
        Ok(())
    }
}
