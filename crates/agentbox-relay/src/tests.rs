//! The handoff, commit and relay in process, over loopback TCP and Unix
//! socket pairs, and the poll and descriptor checks of `unix.rs`; the
//! process itself (adoption of its inherited sockets included) is tested
//! through its Python launcher (tests/server/test_relay.py).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::tunnel::{Bytes, End};
use super::unix;
use super::{receive, serve, Params, Refused, Sockets, ESTABLISHED, MAX_PREFIX, START};

const WAIT: Duration = Duration::from_secs(5);

/// Both ends of one loopback TCP connection: (outside, handed over).
fn tcp() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let outside = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (inside, _) = listener.accept().unwrap();
    outside.set_read_timeout(Some(WAIT)).unwrap();
    (outside, inside)
}

/// (parent, child) control ends; the child's nonblocking.
fn control() -> (UnixStream, UnixStream) {
    let (parent, child) = UnixStream::pair().unwrap();
    child.set_nonblocking(true).unwrap();
    parent.set_read_timeout(Some(WAIT)).unwrap();
    (parent, child)
}

/// The frame without START.
fn frame(idle: u32, lifetime: u32, prefix: &[u8]) -> Vec<u8> {
    let mut frame = b"ABR1".to_vec();
    frame.extend_from_slice(&idle.to_be_bytes());
    frame.extend_from_slice(&lifetime.to_be_bytes());
    frame.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
    frame.extend_from_slice(prefix);
    frame
}

fn started(idle: u32, lifetime: u32, prefix: &[u8]) -> Vec<u8> {
    let mut data = frame(idle, lifetime, prefix);
    data.push(START);
    data
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(300)
}

/// Fresh started sockets: (client outside, upstream outside, sockets, params).
fn handed(prefix: &[u8], idle: Duration) -> (TcpStream, TcpStream, Sockets, Params) {
    let (client, client_in) = tcp();
    let (upstream, upstream_in) = tcp();
    let sockets = Sockets {
        client: client_in,
        upstream: upstream_in,
    };
    let params = Params {
        prefix: prefix.to_vec(),
        idle,
        lifetime: Duration::from_secs(60),
    };
    (client, upstream, sockets, params)
}

fn lines(parent: &mut UnixStream) -> String {
    let mut text = String::new();
    let _ = parent.read_to_string(&mut text);
    text
}

/// Reads the `200` exactly, byte by byte.
fn established(client: &mut TcpStream) -> bool {
    let mut head = vec![0u8; ESTABLISHED.len()];
    client.read_exact(&mut head).is_ok() && head == ESTABLISHED
}

fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let _ = stream.read_to_end(&mut data);
    data
}

// Handoff.

#[test]
fn a_frame_in_pieces_then_start_is_received() {
    let (parent, child) = control();
    let data = started(1000, 2000, b"hello");
    let writer = {
        let mut parent = parent.try_clone().unwrap();
        thread::spawn(move || {
            for byte in data {
                thread::sleep(Duration::from_millis(2));
                parent.write_all(&[byte]).unwrap();
            }
        })
    };
    let params = receive(&child, Instant::now() + WAIT).ok().unwrap();
    writer.join().unwrap();
    assert_eq!(params.prefix, b"hello");
    assert_eq!(params.idle, Duration::from_millis(1000));
    assert_eq!(params.lifetime, Duration::from_millis(2000));
}

#[test]
fn invalid_frames_and_anything_but_start_are_refused() {
    let long = vec![0u8; MAX_PREFIX + 1];
    let mut bad_magic = started(1000, 1000, b"");
    bad_magic[0] = b'X';
    let mut cases = vec![
        bad_magic,
        started(0, 1000, b""),
        started(1000, 0, b""),
        started(1000, 24 * 3600 * 1000 + 1, b""),
        started(1000, 1000, &long),
    ];
    // A revocation byte where START belongs is no START.
    for byte in [b'R', b'U', b'S', 0] {
        let mut data = frame(1000, 1000, b"pre");
        data.push(byte);
        cases.push(data);
    }
    for (round, data) in cases.into_iter().enumerate() {
        let (parent, child) = control();
        (&parent).write_all(&data).unwrap();
        assert_eq!(
            receive(&child, deadline()).err(),
            Some(Refused::Invalid),
            "{round}"
        );
    }
}

#[test]
fn a_stalled_or_vanished_parent_bounds_the_handoff() {
    // Nothing, a partial header, a partial prefix, the frame without
    // START: each times out within the bound.
    let data = frame(1000, 1000, b"prefix");
    for cut in [0, 5, data.len() - 2, data.len()] {
        let (parent, child) = control();
        (&parent).write_all(&data[..cut]).unwrap();
        let begun = Instant::now();
        assert_eq!(receive(&child, deadline()).err(), Some(Refused::Timeout));
        let took = begun.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_secs(1),
            "{took:?}"
        );
    }
    // End of stream midway or just before START: the parent is gone.
    for cut in [5, data.len()] {
        let (parent, child) = control();
        (&parent).write_all(&data[..cut]).unwrap();
        drop(parent);
        assert_eq!(receive(&child, deadline()).err(), Some(Refused::ParentGone));
    }
}

// The descriptor checks and poll of unix.rs.

#[test]
fn only_open_descriptors_are_open() {
    let (a, _b) = UnixStream::pair().unwrap();
    assert!(unix::is_open(a.as_raw_fd()));
    // (A dropped number may be reused at once by a parallel test: only
    // numbers that cannot be open are checked closed.)
    for closed in [1 << 20, -1, i32::MIN] {
        assert!(!unix::is_open(closed), "{closed}");
    }
}

#[test]
fn a_poll_waits_until_its_deadline_and_no_longer() {
    let (a, b) = UnixStream::pair().unwrap();
    for wait in [
        Duration::ZERO,
        Duration::from_micros(300),
        Duration::from_millis(50),
    ] {
        let begun = Instant::now();
        let revents = unix::poll_until(&[(a.as_fd(), unix::IN)], begun + wait).unwrap();
        assert_eq!(revents, vec![0]);
        let took = begun.elapsed();
        assert!(
            took >= wait && took < wait + Duration::from_millis(200),
            "{took:?}"
        );
    }
    (&b).write_all(b"x").unwrap();
    let revents = unix::poll_until(&[(a.as_fd(), unix::IN)], Instant::now() + WAIT).unwrap();
    assert_ne!(revents[0] & unix::IN, 0);
}

/// An expired wait authorizes nothing, however ready its descriptor.
#[test]
fn expired_waits_authorize_nothing_even_when_ready() {
    let (a, b) = UnixStream::pair().unwrap();
    (&b).write_all(b"x").unwrap();
    let now = Instant::now();
    let past = now.checked_sub(Duration::from_millis(5)).unwrap_or(now);
    for deadline in [past, now] {
        let revents = unix::poll_until(&[(a.as_fd(), unix::IN)], deadline).unwrap();
        assert_eq!(revents, vec![0]);
    }
    let revents = unix::poll_until(&[(a.as_fd(), unix::IN)], Instant::now() + WAIT).unwrap();
    assert_ne!(revents[0] & unix::IN, 0);
}

/// A whole frame and START, readable at once but taken past the handoff's
/// bound, start nothing.
#[test]
fn a_ready_handoff_past_its_bound_starts_nothing() {
    let (parent, child) = control();
    (&parent).write_all(&started(1000, 1000, b"pre")).unwrap();
    let now = Instant::now();
    assert_eq!(receive(&child, now).err(), Some(Refused::Timeout));
    let (parent, child) = control();
    (&parent).write_all(&started(1000, 1000, b"pre")).unwrap();
    assert!(receive(&child, Instant::now() + WAIT).is_ok());
}

/// Bytes ready on both sides are never forwarded past the lifetime or the
/// idle bound.
#[test]
fn ready_bytes_are_never_forwarded_past_a_tunnel_bound() {
    for (idle, lifetime_passed, expected) in [
        (WAIT, true, End::LifetimeExceeded),
        (Duration::ZERO, false, End::IdleTimeout),
    ] {
        let (_parent, child) = control();
        let (mut client, mut upstream, sockets, _) = handed(b"", WAIT);
        client.write_all(b"from client").unwrap();
        upstream.write_all(b"from upstream").unwrap();
        thread::sleep(Duration::from_millis(20));
        let Sockets {
            client: client_in,
            upstream: upstream_in,
        } = sockets;
        client_in.set_nonblocking(true).unwrap();
        upstream_in.set_nonblocking(true).unwrap();
        let now = Instant::now();
        let lifetime_end = if lifetime_passed {
            now.checked_sub(Duration::from_millis(1)).unwrap_or(now)
        } else {
            now + WAIT
        };
        let (end, bytes) = super::tunnel::relay(
            &client_in,
            &upstream_in,
            &child,
            b"prefix",
            idle,
            lifetime_end,
        );
        assert_eq!((end, bytes), (expected, Bytes::default()));
        drop((client_in, upstream_in));
        assert_eq!(read_all(&mut client), b"");
        assert_eq!(read_all(&mut upstream), b"");
    }
}

// Commit and relay.

#[test]
fn the_200_comes_first_then_both_streams_with_half_close() {
    let (mut parent, child) = control();
    let (mut client, mut upstream, sockets, params) = handed(b"early", WAIT);
    // A server-first upstream: its bytes wait for the 200.
    upstream.write_all(b"banner").unwrap();
    let served = thread::spawn(move || serve(&child, sockets, params));
    assert!(established(&mut client));
    let mut banner = [0u8; 6];
    client.read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"banner");
    client.write_all(b" and more").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(read_all(&mut upstream), b"early and more");
    upstream.write_all(b" bye").unwrap();
    upstream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(read_all(&mut client), b" bye");
    let (end, bytes) = served.join().unwrap();
    assert_eq!(end, End::Completed);
    assert_eq!(bytes, Bytes { up: 14, down: 10 });
    let mut opened = [0u8; 7];
    parent.read_exact(&mut opened).unwrap();
    assert_eq!(&opened, b"opened\n");
}

#[test]
fn a_revocation_after_start_before_the_200_prevents_it() {
    for (byte, expected) in [
        (b'R', End::Revoked),
        (b'U', End::TopologyUnavailable),
        (b'S', End::Stopped),
    ] {
        let (mut parent, child) = control();
        let (mut client, mut upstream, sockets, params) = handed(b"", WAIT);
        parent.write_all(&[byte]).unwrap();
        let (end, bytes) = serve(&child, sockets, params);
        assert_eq!((end, bytes), (expected, Bytes::default()));
        assert_eq!(read_all(&mut client), b"");
        assert_eq!(read_all(&mut upstream), b"");
        drop(child);
        assert_eq!(lines(&mut parent), "");
    }
    // Gone before the commit: no 200 either.
    let (parent, child) = control();
    let (mut client, _upstream, sockets, params) = handed(b"", WAIT);
    drop(parent);
    assert_eq!(serve(&child, sockets, params).0, End::ParentGone);
    assert_eq!(read_all(&mut client), b"");
}

/// Both peers stalled with full buffers: a revocation or the parent's end
/// of stream still ends the tunnel at once.
#[test]
fn stalled_peers_do_not_delay_a_revocation_or_a_vanished_parent() {
    for revoke in [true, false] {
        let (mut parent, child) = control();
        let (mut client, upstream, sockets, params) = handed(b"", WAIT);
        let served = thread::spawn(move || serve(&child, sockets, params));
        assert!(established(&mut client));
        // Neither peer reads: fill both directions until writes block.
        for stream in [&client, &upstream] {
            stream.set_nonblocking(true).unwrap();
            let chunk = [1u8; 64 * 1024];
            let started = Instant::now();
            let mut blocked = 0;
            while blocked < 10 {
                assert!(started.elapsed() < WAIT);
                match (&*stream).write(&chunk) {
                    Ok(n) => blocked = if n > 0 { 0 } else { blocked },
                    Err(_) => {
                        blocked += 1;
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        let started = Instant::now();
        if revoke {
            parent.write_all(b"R").unwrap();
        } else {
            drop(parent);
        }
        let (end, _) = served.join().unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        let expected = if revoke {
            End::Revoked
        } else {
            End::ParentGone
        };
        assert_eq!(end, expected);
    }
}

#[test]
fn an_idle_tunnel_ends() {
    let (_parent, child) = control();
    let (mut client, _upstream, sockets, params) = handed(b"", Duration::from_millis(100));
    let started = Instant::now();
    let served = thread::spawn(move || serve(&child, sockets, params));
    assert!(established(&mut client));
    assert_eq!(served.join().unwrap().0, End::IdleTimeout);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(read_all(&mut client), b"");
}

#[test]
fn a_reset_upstream_ends_the_tunnel() {
    let (_parent, child) = control();
    let (mut client, upstream, sockets, params) = handed(b"", WAIT);
    let served = thread::spawn(move || serve(&child, sockets, params));
    assert!(established(&mut client));
    // Unread data at close resets the connection.
    client.write_all(b"unread").unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(upstream);
    client.write_all(b"more").unwrap();
    assert_eq!(served.join().unwrap().0, End::UpstreamReset);
}
