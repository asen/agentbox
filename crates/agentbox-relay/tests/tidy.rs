//! The relay child's sources: unsafe code only in `unix.rs`, exactly two
//! one-line `unsafe` expressions there (the adoption of its inherited
//! sockets and `poll(2)`), each allowed by name and justified; unsafe code
//! denied everywhere else (also by the package's lints); no dependency on
//! the server's crate; nothing that resolves, dials or listens.

use std::fs;
use std::path::Path;

fn code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_relay_child_stays_small_unsafe_and_apart() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = fs::read_to_string(dir.join("main.rs")).unwrap();
    assert!(main.contains("\n#![deny(unsafe_code)]\n"));
    let mut seen = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let text = fs::read_to_string(&path).unwrap();
        let code = code(&text).replace("#![deny(unsafe_code)]", "");
        if name == "unix.rs" {
            assert_eq!(code.matches("unsafe").count(), 4, "two allows, two blocks");
            assert_eq!(code.matches("#[allow(unsafe_code)]").count(), 2);
            let blocks: Vec<&str> = code
                .lines()
                .filter(|line| line.contains("unsafe {"))
                .collect();
            assert_eq!(blocks.len(), 2);
            assert!(
                blocks[0].trim() == "unsafe { OwnedFd::from_raw_fd(fd) }",
                "{}",
                blocks[0]
            );
            assert!(blocks[1].contains("unsafe { libc::poll(fds.as_mut_ptr(), len, timeout) };"));
            assert_eq!(text.matches("// SAFETY:").count(), 2);
            // The adopter: its definition and its two calls, both in
            // `adopt_inherited` (itself called once, by `run`).
            assert_eq!(
                code.matches("adopt(").count(),
                3,
                "definition and two calls"
            );
        } else {
            assert!(!code.contains("unsafe"), "{name} uses unsafe");
            assert!(!code.contains("from_raw_fd"), "{name} adopts descriptors");
        }
        for banned in [
            "agentbox::",
            "ToSocketAddrs",
            "lookup_host",
            "std::process::Command",
            "UdpSocket",
        ] {
            assert!(!code.contains(banned), "{name} uses {banned}");
        }
        // The tests make their own loopback fixtures.
        if name != "tests.rs" {
            for banned in ["TcpListener", "connect(", "bind("] {
                assert!(!code.contains(banned), "{name} uses {banned}");
            }
        }
        seen += 1;
    }
    assert_eq!(seen, 4);
    assert_eq!(main.matches("unix::adopt_inherited()").count(), 1);
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(
        !manifest.contains("agentbox ="),
        "the relay never depends on the server's crate"
    );
    assert!(manifest.contains("unsafe_code = \"deny\""));
}
