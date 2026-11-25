//! The relay's only unsafe code, two expressions: adopting its two
//! inherited sockets (once per process) and `poll(2)`. Everything around
//! them is safe checking. Nothing here is a general raw-descriptor API: the
//! only descriptors ever adopted are the two named by this process's own
//! arguments, before it has made any descriptor of its own.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub(crate) const IN: i16 = libc::POLLIN;
pub(crate) const OUT: i16 = libc::POLLOUT;

/// Whether `adopt_inherited` ran: it adopts at most once per process.
static ADOPTED: AtomicBool = AtomicBool::new(false);

/// Why the inherited sockets were not adopted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invocation {
    /// Not exactly two canonical decimal numbers above 2, distinct.
    Arguments,
    /// A named descriptor is not open.
    NotOpen,
    /// Already called in this process.
    Again,
}

/// The client and upstream sockets this process inherited, named by its
/// two arguments (decimal descriptor numbers), as owned descriptors. Both
/// or neither: each number canonical, above 2, distinct from the other and
/// open (`POLLNVAL` not set). `main` calls it first, before anything that
/// creates a descriptor (duplicating stdin included), so a missing number
/// can never be one of this process's own; a second call is refused.
pub(crate) fn adopt_inherited() -> Result<(OwnedFd, OwnedFd), Invocation> {
    if ADOPTED.swap(true, Ordering::SeqCst) {
        return Err(Invocation::Again);
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let [client, upstream] = args.as_slice() else {
        return Err(Invocation::Arguments);
    };
    let (Some(client), Some(upstream)) = (number(client), number(upstream)) else {
        return Err(Invocation::Arguments);
    };
    if client == upstream {
        return Err(Invocation::Arguments);
    }
    if !is_open(client) || !is_open(upstream) {
        return Err(Invocation::NotOpen);
    }
    Ok((adopt(client), adopt(upstream)))
}

/// A canonical decimal descriptor number above 2: digits only, no sign or
/// leading zero, at most `RawFd::MAX`.
fn number(text: &OsString) -> Option<RawFd> {
    let text = text.to_str()?;
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<RawFd>().ok().filter(|fd| *fd > 2)
}

/// Owns `fd`; only `adopt_inherited` calls it.
#[allow(unsafe_code)]
fn adopt(fd: RawFd) -> OwnedFd {
    // SAFETY: called only by `adopt_inherited`, which runs at most once per
    // process (`ADOPTED`), for two distinct numbers above 2 that poll(2)
    // found open. They name descriptors inherited at exec (the launcher's
    // `pass_fds`): `main` calls `adopt_inherited` before it creates any
    // descriptor, std's startup only ever reopens 0, 1 and 2, and nothing
    // else in this process has opened, borrowed or owned them. So the
    // returned `OwnedFd` is their only owner and closes each once.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// Whether descriptor number `fd` is open in this process; it is neither
/// borrowed nor owned.
pub(crate) fn is_open(fd: RawFd) -> bool {
    // poll(2) ignores a negative number rather than flag it.
    if fd < 0 {
        return false;
    }
    let mut fds = [libc::pollfd {
        fd,
        events: 0,
        revents: 0,
    }];
    loop {
        match sys_poll(&mut fds, 0) {
            Ok(_) => return fds[0].revents & libc::POLLNVAL == 0,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// Waits until one of `fds` is ready for its events (or failed or hung
/// up) before `deadline`: their `revents`; all zero once the deadline has
/// passed, ready or not. An expired wait authorizes nothing: at or past the
/// deadline nothing is polled, and readiness seen only then is dropped.
/// The deadline is monotonic and absolute: an interrupted wait resumes
/// with what is left; timeouts round up to whole milliseconds, so it never
/// returns early with nothing. (`is_open` is the one deliberate
/// non-waiting poll, of a number's validity alone.)
pub(crate) fn poll_until(fds: &[(BorrowedFd<'_>, i16)], deadline: Instant) -> io::Result<Vec<i16>> {
    let mut entries: Vec<libc::pollfd> = fds
        .iter()
        .map(|(fd, events)| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: *events,
            revents: 0,
        })
        .collect();
    let expired = vec![0; entries.len()];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(expired);
        }
        let left = (deadline - now).as_nanos().div_ceil(1_000_000);
        let timeout = libc::c_int::try_from(left).unwrap_or(libc::c_int::MAX);
        match sys_poll(&mut entries, timeout) {
            Ok(_) if Instant::now() >= deadline => return Ok(expired),
            Ok(0) => {}
            Ok(_) => return Ok(entries.iter().map(|entry| entry.revents).collect()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[allow(unsafe_code)]
fn sys_poll(fds: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<usize> {
    let len = libc::nfds_t::try_from(fds.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `fds` is an exclusively borrowed slice of `len` initialized
    // `pollfd`s; poll(2) reads their `fd` and `events`, writes only their
    // `revents` and keeps no pointer once it returns. Any descriptor
    // number, open or not, is memory-safe to poll.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), len, timeout) };
    usize::try_from(ready).map_err(|_| io::Error::last_os_error())
}
