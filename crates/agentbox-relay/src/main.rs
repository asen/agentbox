//! `agentbox-relay`: the payload of one approved CONNECT tunnel, in its own
//! process, started by the broker (src/agentbox_server/relay.py).
//!
//! Its trusted parent has read the request head, admitted the request and
//! dialed the approved address. The child inherits both connected sockets
//! at their own descriptor numbers, named by its two arguments, and is
//! sent the bytes read past the head. It never resolves, dials, listens,
//! reads policy or parses the payload.
//!
//! ```text
//! parent                                    agentbox-relay CLIENT_FD UPSTREAM_FD
//! socketpair(AF_UNIX, STREAM): one end is   adopts both (distinct, above 2, open)
//!   the child's stdin; stdout and stderr    before it makes any descriptor
//!   /dev/null; nothing else inherited
//! frame: "ABR1" idle_ms:u32 lifetime_ms:u32 prefix_len:u16 prefix START
//!   (big endian; prefix at most 16 KiB; START = "G")
//!                                       ---> all of it within HANDOFF_WAIT
//!                                       <--- "refused <reason>\n", exit 2
//! closes its own client and upstream once START is written
//! one byte: R revoked, U unavailable,       ---> no 200 if heard first
//!   anything else stopped
//!                                       <--- "opened\n": the 200 was sent
//!                                             relay: prefix first, one
//!                                             16 KiB buffer per direction
//!                                       <--- "closed <reason> <up> <down>\n"
//! end of stream (parent gone)               ---> exit 3, no line
//! ```
//!
//! START is the ownership boundary. Before it the child neither reads,
//! writes nor shuts down either socket: a refusal, an invalid or partial
//! frame, any byte but START, or the parent's end of stream only drops its
//! copies, and the parent may still answer the client itself. After it only
//! the child writes to the client: the `200`, at most once and only as one
//! whole nonblocking write, and then payload. Every wait is bounded and
//! monotonic: the handoff by `HANDOFF_WAIT`, each status line by
//! `STATUS_WAIT`, the tunnel by its idle and lifetime bounds; a revocation
//! or the parent's end of stream is seen at the next poll, which also waits
//! for the control socket. The only unsafe code is in `unix.rs`.

#![deny(unsafe_code)]

mod tunnel;
mod unix;

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use tunnel::End;

/// From start to the whole frame and START.
const HANDOFF_WAIT: Duration = Duration::from_secs(2);
/// One status line, the parent slow to read it.
const STATUS_WAIT: Duration = Duration::from_secs(1);
const MAGIC: &[u8; 4] = b"ABR1";
/// After the frame: the parent committed, the sockets are the child's.
const START: u8 = b'G';
const HEADER_BYTES: usize = 14;
const MAX_PREFIX: usize = tunnel::BUFFER_BYTES;
const MAX_MILLIS: u32 = 24 * 3600 * 1000;
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

const EXIT_REPORTED: i32 = 0;
const EXIT_REFUSED: i32 = 2;
const EXIT_PARENT_GONE: i32 = 3;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    // First: nothing has made a descriptor yet, so a missing number cannot
    // be one of ours.
    let adopted = unix::adopt_inherited();
    let Ok(control) = control() else {
        return EXIT_REFUSED;
    };
    let Ok((client, upstream)) = adopted else {
        report(&control, "refused invocation_invalid\n");
        return EXIT_REFUSED;
    };
    let Some(sockets) = Sockets::checked(client, upstream) else {
        report(&control, "refused invocation_invalid\n");
        return EXIT_REFUSED;
    };
    let params = match receive(&control, Instant::now() + HANDOFF_WAIT) {
        Ok(params) => params,
        // Not started: the sockets are only dropped, never touched.
        Err(Refused::ParentGone) => return EXIT_PARENT_GONE,
        Err(refused) => {
            drop(sockets);
            report(&control, &format!("refused {}\n", refused.as_str()));
            return EXIT_REFUSED;
        }
    };
    let (end, bytes) = serve(&control, sockets, params);
    if end == End::ParentGone {
        return EXIT_PARENT_GONE;
    }
    // Every socket is closed before the last line.
    let line = format!("closed {} {} {}\n", end.as_str(), bytes.up, bytes.down);
    report(&control, &line);
    EXIT_REPORTED
}

/// The control socket: a duplicate of stdin, nonblocking.
fn control() -> io::Result<UnixStream> {
    let control = UnixStream::from(io::stdin().as_fd().try_clone_to_owned()?);
    control.set_nonblocking(true)?;
    Ok(control)
}

/// The adopted sockets, both connected TCP streams.
struct Sockets {
    client: TcpStream,
    upstream: TcpStream,
}

impl Sockets {
    /// Both or neither: a socket that is not a connected TCP stream drops
    /// both, untouched.
    fn checked(client: OwnedFd, upstream: OwnedFd) -> Option<Sockets> {
        let (client, upstream) = (TcpStream::from(client), TcpStream::from(upstream));
        let tcp = |stream: &TcpStream| stream.nodelay().is_ok() && stream.peer_addr().is_ok();
        (tcp(&client) && tcp(&upstream)).then_some(Sockets { client, upstream })
    }
}

/// What the frame says.
struct Params {
    prefix: Vec<u8>,
    idle: Duration,
    lifetime: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    Timeout,
    Invalid,
    ParentGone,
}

impl Refused {
    fn as_str(self) -> &'static str {
        match self {
            Refused::Timeout => "handoff_timeout",
            Refused::Invalid => "handoff_invalid",
            Refused::ParentGone => "parent_gone",
        }
    }
}

/// The whole frame, then START, by `deadline`.
fn receive(control: &UnixStream, deadline: Instant) -> Result<Params, Refused> {
    let mut header = [0u8; HEADER_BYTES];
    fill(control, &mut header, deadline)?;
    let word = |at: usize| {
        u32::from_be_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
    };
    let (idle, lifetime) = (word(4), word(8));
    let prefix_len = u16::from_be_bytes([header[12], header[13]]) as usize;
    let valid = &header[..4] == MAGIC
        && (1..=MAX_MILLIS).contains(&idle)
        && (1..=MAX_MILLIS).contains(&lifetime)
        && prefix_len <= MAX_PREFIX;
    if !valid {
        return Err(Refused::Invalid);
    }
    let mut prefix = vec![0u8; prefix_len];
    fill(control, &mut prefix, deadline)?;
    let mut start = [0u8];
    fill(control, &mut start, deadline)?;
    if start[0] != START {
        return Err(Refused::Invalid);
    }
    // Taken only within the bound: a handoff completed past it starts
    // nothing.
    if Instant::now() >= deadline {
        return Err(Refused::Timeout);
    }
    Ok(Params {
        prefix,
        idle: Duration::from_millis(idle.into()),
        lifetime: Duration::from_millis(lifetime.into()),
    })
}

/// Fills `buf` exactly from the control socket by `deadline`.
fn fill(control: &UnixStream, buf: &mut [u8], deadline: Instant) -> Result<(), Refused> {
    let mut got = 0;
    while got < buf.len() {
        if !wait(control, unix::IN, deadline) || Instant::now() >= deadline {
            return Err(Refused::Timeout);
        }
        match (&*control).read(&mut buf[got..]) {
            Ok(0) => return Err(Refused::ParentGone),
            Ok(n) => got += n,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(_) => return Err(Refused::Invalid),
        }
    }
    Ok(())
}

/// Whether `fd` became ready for `events`, or failed, before `deadline`.
pub(crate) fn wait(fd: &impl AsFd, events: i16, deadline: Instant) -> bool {
    match unix::poll_until(&[(fd.as_fd(), events)], deadline) {
        Ok(revents) => revents[0] != 0,
        // The next operation reports it.
        Err(_) => true,
    }
}

/// One status line, within `STATUS_WAIT`; `false` when not all written.
fn report(control: &UnixStream, line: &str) -> bool {
    let deadline = Instant::now() + STATUS_WAIT;
    let mut data = line.as_bytes();
    while !data.is_empty() {
        match (&*control).write(data) {
            Ok(0) => return false,
            Ok(n) => data = &data[n..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if !wait(control, unix::OUT, deadline) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

/// After START: the `200` unless the parent spoke first, then the relay;
/// both sockets are closed on return.
fn serve(control: &UnixStream, sockets: Sockets, params: Params) -> (End, tunnel::Bytes) {
    let Sockets { client, upstream } = sockets;
    let Params {
        prefix,
        idle,
        lifetime,
    } = params;
    let lifetime_end = Instant::now() + lifetime;
    let end = commit(control, &client, &upstream);
    let (end, bytes) = match end {
        Some(end) => (end, tunnel::Bytes::default()),
        None => tunnel::relay(&client, &upstream, control, &prefix, idle, lifetime_end),
    };
    if end != End::Completed {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
    }
    (end, bytes)
}

/// The last check and one nonblocking attempt at the whole `200`; `None`
/// once sent and reported.
fn commit(control: &UnixStream, client: &TcpStream, upstream: &TcpStream) -> Option<End> {
    if client.set_nonblocking(true).is_err() {
        return Some(End::ClientReset);
    }
    if upstream.set_nonblocking(true).is_err() {
        return Some(End::UpstreamReset);
    }
    if let Some(end) = tunnel::heard(control) {
        return Some(end);
    }
    if !matches!((&*client).write(ESTABLISHED), Ok(n) if n == ESTABLISHED.len()) {
        return Some(End::ClientReset);
    }
    // A parent gone meanwhile is seen at the relay's first poll.
    report(control, "opened\n");
    None
}

#[cfg(test)]
mod tests;
