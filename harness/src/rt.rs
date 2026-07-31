//! Raw Linux syscalls, so the harness needs neither libc nor `std`.
//!
//! The point of the harness is to run the *same* `no_std` library crates the
//! firmware runs. Linking libc would quietly reintroduce an allocator, a
//! threading runtime, and a pile of hosted assumptions the ESP32 does not have,
//! and the test would stop proving what it claims to prove. Talking to the
//! kernel directly keeps the environment as bare as the chip's.

use core::arch::asm;

// x86_64 Linux syscall numbers.
const SYS_WRITE: usize = 1;
const SYS_POLL: usize = 7;
const SYS_SOCKET: usize = 41;
const SYS_SENDTO: usize = 44;
const SYS_RECVFROM: usize = 45;
const SYS_BIND: usize = 49;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const SYS_GETRANDOM: usize = 318;

pub const AF_INET: u16 = 2;
pub const SOCK_DGRAM: usize = 2;
pub const POLLIN: i16 = 1;
pub const CLOCK_MONOTONIC: usize = 1;

pub const STDOUT: i32 = 1;

/// A negative return value from a syscall is `-errno`.
fn check(ret: isize) -> Result<usize, i32> {
    if (-4095..0).contains(&ret) {
        Err(-ret as i32)
    } else {
        Ok(ret as usize)
    }
}

unsafe fn syscall3(n: usize, a: usize, b: usize, c: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a, in("rsi") b, in("rdx") c,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

unsafe fn syscall6(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a, in("rsi") b, in("rdx") c,
            in("r10") d, in("r8") e, in("r9") f,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

pub fn write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    check(unsafe { syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) })
}

pub fn exit(code: i32) -> ! {
    unsafe { syscall3(SYS_EXIT_GROUP, code as usize, 0, 0) };
    // exit_group does not return; this is only here to satisfy the `!` type.
    loop {
        core::hint::spin_loop();
    }
}

pub fn getrandom(buf: &mut [u8]) -> Result<usize, i32> {
    check(unsafe { syscall3(SYS_GETRANDOM, buf.as_mut_ptr() as usize, buf.len(), 0) })
}

/// Milliseconds from the monotonic clock.
pub fn monotonic_millis() -> u64 {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    let mut ts = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    unsafe {
        syscall3(
            SYS_CLOCK_GETTIME,
            CLOCK_MONOTONIC,
            &raw mut ts as usize,
            0,
        )
    };
    (ts.seconds as u64) * 1_000 + (ts.nanoseconds as u64) / 1_000_000
}

/// `struct sockaddr_in`. Port and address are network byte order; the family is
/// host byte order, which is why only some fields are byte-swapped below.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

impl SockAddrIn {
    pub fn new(address: [u8; 4], port: u16) -> Self {
        Self {
            family: AF_INET,
            port: port.to_be(),
            address,
            zero: [0; 8],
        }
    }
}

pub fn socket_udp() -> Result<i32, i32> {
    check(unsafe { syscall3(SYS_SOCKET, AF_INET as usize, SOCK_DGRAM, 0) }).map(|fd| fd as i32)
}

pub fn bind(fd: i32, addr: &SockAddrIn) -> Result<(), i32> {
    check(unsafe {
        syscall3(
            SYS_BIND,
            fd as usize,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
        )
    })
    .map(|_| ())
}

pub fn send_to(fd: i32, buf: &[u8], addr: &SockAddrIn) -> Result<usize, i32> {
    check(unsafe {
        syscall6(
            SYS_SENDTO,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            0,
            addr as *const SockAddrIn as usize,
            core::mem::size_of::<SockAddrIn>(),
        )
    })
}

pub fn recv_from(fd: i32, buf: &mut [u8]) -> Result<(usize, SockAddrIn), i32> {
    let mut addr = SockAddrIn::new([0; 4], 0);
    let mut addr_len = core::mem::size_of::<SockAddrIn>() as u32;
    let n = check(unsafe {
        syscall6(
            SYS_RECVFROM,
            fd as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            0,
            &raw mut addr as usize,
            &raw mut addr_len as usize,
        )
    })?;
    Ok((n, addr))
}

/// Wait until `fd` is readable or `timeout_ms` elapses. Returns whether data is
/// ready.
pub fn poll_readable(fd: i32, timeout_ms: i32) -> Result<bool, i32> {
    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    let mut pfd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    let ready = check(unsafe {
        syscall3(SYS_POLL, &raw mut pfd as usize, 1, timeout_ms as usize)
    })?;
    Ok(ready > 0 && pfd.revents & POLLIN != 0)
}

/// Writes to stdout, so the harness can report without `std`.
pub struct Console;

impl core::fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write(STDOUT, s.as_bytes()).map(|_| ()).map_err(|_| core::fmt::Error)
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::rt::Console, $($arg)*);
    }};
}
