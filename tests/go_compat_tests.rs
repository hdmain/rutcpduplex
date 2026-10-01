//! Go ↔ Rust protocol compatibility tests.
//!
//! Requires Go toolchain and builds `tests/go_compat` against the local `_go_ref`
//! checkout (or crates.io / module cache of `github.com/hdmain/tcpduplex`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use rutcpduplex::{dial, dial_with_config, serve_conn, Config, HandshakeAuth};

fn go_peer_bin() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("tests").join("go_compat");
    let out = dir.join(if cfg!(windows) { "peer.exe" } else { "peer" });
    if out.exists() {
        // Rebuild if source is newer would be nicer; always rebuild for CI reliability.
    }
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&out)
        .arg(".")
        .current_dir(&dir)
        .status()
        .expect("go build failed to start — is Go installed?");
    assert!(status.success(), "go build go_compat peer failed");
    out
}

fn read_len_prefixed(stdout: &mut impl Read) -> Vec<u8> {
    let mut hdr = [0u8; 4];
    stdout.read_exact(&mut hdr).expect("read len");
    let n = u32::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; n];
    stdout.read_exact(&mut buf).expect("read payload");
    buf
}

#[test]
fn rust_client_go_server() {
    let bin = go_peer_bin();
    let mut child = Command::new(&bin)
        .args(["-mode", "server", "-addr", "127.0.0.1:0", "-msg", "hello-from-rust"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn go server");

    let mut stdout = child.stdout.take().unwrap();
    let addr = String::from_utf8(read_len_prefixed(&mut stdout)).unwrap();

    let cli = dial(&addr).expect("rust dial go");
    cli.send(b"hello-from-rust").unwrap();
    let ack = cli.receive().unwrap();
    assert_eq!(ack, b"ack-from-go");
    let _ = cli.close();

    let status = child.wait().unwrap();
    assert!(status.success(), "go server exit: {status}");
}

#[test]
fn go_client_rust_server() {
    let bin = go_peer_bin();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();

    let srv_thread = thread::spawn(move || {
        let (stream, _) = ln.accept().unwrap();
        let srv = serve_conn(stream).unwrap();
        let msg = srv.receive().unwrap();
        assert_eq!(msg, b"hello-from-go");
        srv.send(b"ack-from-rust").unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ = srv.close();
    });

    // Give the listener a moment.
    thread::sleep(Duration::from_millis(50));

    let mut child = Command::new(&bin)
        .args([
            "-mode",
            "client",
            "-addr",
            &addr,
            "-msg",
            "hello-from-go",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn go client");

    let mut stdout = child.stdout.take().unwrap();
    let got = read_len_prefixed(&mut stdout);
    assert_eq!(got, b"ack-from-rust");

    let status = child.wait().unwrap();
    assert!(status.success(), "go client exit: {status}");
    srv_thread.join().unwrap();
}

#[test]
fn rust_client_go_server_psk() {
    let bin = go_peer_bin();
    let mut child = Command::new(&bin)
        .args([
            "-mode",
            "server",
            "-addr",
            "127.0.0.1:0",
            "-msg",
            "psk-hi",
            "-psk",
            "shared-secret",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn go server");

    let mut stdout = child.stdout.take().unwrap();
    let addr = String::from_utf8(read_len_prefixed(&mut stdout)).unwrap();

    let mut cfg = Config::default_config();
    cfg.handshake = HandshakeAuth {
        pre_shared_key: b"shared-secret".to_vec(),
        expected_peer_pub_key_sha256: None,
    };
    let cli = dial_with_config(&addr, Some(&cfg)).expect("rust dial go psk");
    cli.send(b"psk-hi").unwrap();
    assert_eq!(cli.receive().unwrap(), b"ack-from-go");
    let _ = cli.close();
    assert!(child.wait().unwrap().success());
}

#[test]
fn go_client_rust_server_psk() {
    let bin = go_peer_bin();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();

    let mut cfg = Config::default_config();
    cfg.handshake = HandshakeAuth {
        pre_shared_key: b"shared-secret".to_vec(),
        expected_peer_pub_key_sha256: None,
    };
    let cfg2 = cfg.clone();
    let srv_thread = thread::spawn(move || {
        let (stream, _) = ln.accept().unwrap();
        let srv = rutcpduplex::serve_conn_with_config(stream, Some(&cfg2)).unwrap();
        assert_eq!(srv.receive().unwrap(), b"hello-from-go");
        srv.send(b"ack-from-rust").unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ = srv.close();
    });

    thread::sleep(Duration::from_millis(50));
    let mut child = Command::new(&bin)
        .args([
            "-mode",
            "client",
            "-addr",
            &addr,
            "-msg",
            "hello-from-go",
            "-psk",
            "shared-secret",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    assert_eq!(read_len_prefixed(&mut stdout), b"ack-from-rust");
    assert!(child.wait().unwrap().success());
    srv_thread.join().unwrap();
}

// Silence unused import if Write not needed on some platforms.
#[allow(dead_code)]
fn _touch_write(w: &mut dyn Write) {
    let _ = w;
}
