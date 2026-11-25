//! The byte relay of one tunnel and its control socket.
//!
//! Bytes are copied as they are, in both directions, with partial reads and
//! writes and half-close: a side's end of stream is passed on as a write
//! shutdown once its buffered bytes are written. Each direction holds one
//! buffer, read only when empty, so a stalled side stops the other's reads.
//! One poll waits for both sockets and the control socket, at most until
//! the idle or lifetime end.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::unix;

/// Per direction; the prefix fits in the first.
pub(crate) const BUFFER_BYTES: usize = 16 * 1024;

/// Why a tunnel ended; the strings are the broker's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// Both sides ended their streams and every byte was passed on.
    Completed,
    ClientReset,
    UpstreamReset,
    IdleTimeout,
    LifetimeExceeded,
    Revoked,
    TopologyUnavailable,
    Stopped,
    /// The control socket's end of stream: nothing is reported.
    ParentGone,
}

impl End {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            End::Completed => "completed",
            End::ClientReset => "client_reset",
            End::UpstreamReset => "upstream_reset",
            End::IdleTimeout => "idle_timeout",
            End::LifetimeExceeded => "lifetime_exceeded",
            End::Revoked => "topology_revoked",
            End::TopologyUnavailable => "topology_unavailable",
            End::Stopped => "broker_stopped",
            End::ParentGone => "parent_gone",
        }
    }
}

/// What the parent said, without waiting: `None` while nothing.
pub(crate) fn heard(control: &UnixStream) -> Option<End> {
    let mut buf = [0u8; 16];
    match (&*control).read(&mut buf) {
        Ok(0) => Some(End::ParentGone),
        Ok(_) => Some(match buf[0] {
            b'R' => End::Revoked,
            b'U' => End::TopologyUnavailable,
            _ => End::Stopped,
        }),
        Err(error) if retry(&error) => None,
        Err(_) => Some(End::ParentGone),
    }
}

/// Bytes forwarded by one tunnel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Bytes {
    pub up: u64,
    pub down: u64,
}

struct Half {
    buf: Vec<u8>,
    start: usize,
    end: usize,
    eof: bool,
    shut: bool,
    forwarded: u64,
    /// The end reported when the source fails.
    reset: End,
}

impl Half {
    fn new(prefix: &[u8], reset: End) -> Half {
        let mut buf = vec![0; BUFFER_BYTES.max(prefix.len())];
        buf[..prefix.len()].copy_from_slice(prefix);
        Half {
            buf,
            start: 0,
            end: prefix.len(),
            eof: false,
            shut: false,
            forwarded: 0,
            reset,
        }
    }

    fn pending(&self) -> bool {
        self.start < self.end
    }

    fn wants_read(&self) -> bool {
        !self.eof && !self.pending()
    }

    fn done(&self) -> bool {
        self.eof && self.shut && !self.pending()
    }

    /// One read into the empty buffer; `Err` ends the tunnel.
    fn read(&mut self, src: &TcpStream) -> Result<bool, End> {
        match (&*src).read(&mut self.buf) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(n) => {
                self.start = 0;
                self.end = n;
                Ok(true)
            }
            Err(error) if retry(&error) => Ok(false),
            Err(_) => Err(self.reset),
        }
    }

    /// One write of the buffered bytes; `Err` ends the tunnel.
    fn write(&mut self, dst: &TcpStream, dst_reset: End) -> Result<bool, End> {
        match (&*dst).write(&self.buf[self.start..self.end]) {
            Ok(n) => {
                self.start += n;
                self.forwarded += n as u64;
                Ok(n > 0)
            }
            Err(error) if retry(&error) => Ok(false),
            Err(_) => Err(dst_reset),
        }
    }

    fn finish(&mut self, dst: &TcpStream, dst_reset: End) -> Result<(), End> {
        if self.eof && !self.shut && !self.pending() {
            self.shut = true;
            dst.shutdown(Shutdown::Write).map_err(|_| dst_reset)?;
        }
        Ok(())
    }

    fn events(&self, other: &Half) -> i16 {
        let mut events = 0;
        if self.wants_read() {
            events |= unix::IN;
        }
        if other.pending() {
            events |= unix::OUT;
        }
        events
    }
}

fn retry(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted)
}

/// Relays between two connected nonblocking sockets until both streams
/// end, a side fails, a bound passes or the parent speaks or goes. `prefix`
/// is what the client sent after its request head.
pub(crate) fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    control: &UnixStream,
    prefix: &[u8],
    idle: Duration,
    lifetime_end: Instant,
) -> (End, Bytes) {
    let mut up = Half::new(prefix, End::ClientReset);
    let mut down = Half::new(&[], End::UpstreamReset);
    let end = run(
        client,
        upstream,
        control,
        &mut up,
        &mut down,
        idle,
        lifetime_end,
    );
    let bytes = Bytes {
        up: up.forwarded,
        down: down.forwarded,
    };
    (end, bytes)
}

fn run(
    client: &TcpStream,
    upstream: &TcpStream,
    control: &UnixStream,
    up: &mut Half,
    down: &mut Half,
    idle: Duration,
    lifetime_end: Instant,
) -> End {
    let mut active = Instant::now();
    loop {
        if up.done() && down.done() {
            return End::Completed;
        }
        let now = Instant::now();
        if now >= lifetime_end {
            return End::LifetimeExceeded;
        }
        let idle_end = active + idle;
        if now >= idle_end {
            return End::IdleTimeout;
        }
        // A socket with nothing wanted is left out: its hangup would
        // otherwise wake every poll.
        let (client_events, upstream_events) = (up.events(down), down.events(up));
        let mut fds = vec![(control.as_fd(), unix::IN)];
        if client_events != 0 {
            fds.push((client.as_fd(), client_events));
        }
        if upstream_events != 0 {
            fds.push((upstream.as_fd(), upstream_events));
        }
        let revents = match unix::poll_until(&fds, lifetime_end.min(idle_end)) {
            Ok(revents) => revents,
            Err(_) => return End::Stopped,
        };
        let mut ready = revents.iter().map(|revents| *revents != 0);
        let spoke = ready.next() == Some(true);
        let client_ready = client_events != 0 && ready.next() == Some(true);
        let upstream_ready = upstream_events != 0 && ready.next() == Some(true);
        if spoke {
            if let Some(end) = heard(control) {
                return end;
            }
        }
        // Readiness forwards nothing past either bound.
        let now = Instant::now();
        if now >= lifetime_end {
            return End::LifetimeExceeded;
        }
        if now >= idle_end {
            return End::IdleTimeout;
        }
        match step(client, upstream, up, down, [client_ready, upstream_ready]) {
            Ok(true) => active = Instant::now(),
            Ok(false) => {}
            Err(end) => return end,
        }
    }
}

/// One round of writes, reads and write shutdowns after a poll; `Ok(true)`
/// when any byte moved or a stream ended.
fn step(
    client: &TcpStream,
    upstream: &TcpStream,
    up: &mut Half,
    down: &mut Half,
    [client_ready, upstream_ready]: [bool; 2],
) -> Result<bool, End> {
    let mut progress = false;
    if upstream_ready && up.pending() {
        progress |= up.write(upstream, End::UpstreamReset)?;
    }
    if client_ready && down.pending() {
        progress |= down.write(client, End::ClientReset)?;
    }
    if client_ready && up.wants_read() {
        progress |= up.read(client)?;
    }
    if upstream_ready && down.wants_read() {
        progress |= down.read(upstream)?;
    }
    up.finish(upstream, End::UpstreamReset)?;
    down.finish(client, End::ClientReset)?;
    Ok(progress)
}
