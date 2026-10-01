//! Unit / integration tests for rutcpduplex.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rutcpduplex::transfer::{receive_mem, send_bytes, MemFile, Options};
use rutcpduplex::{dial, dial_with_config, serve_conn, Config, Error, HandshakeAuth};

fn paired() -> (std::sync::Arc<rutcpduplex::Conn>, std::sync::Arc<rutcpduplex::Conn>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (s, _) = ln.accept().unwrap();
        serve_conn(s).unwrap()
    });
    let cli = dial(&addr.to_string()).unwrap();
    let srv = handle.join().unwrap();
    (cli, srv)
}

#[test]
fn send_receive_roundtrip() {
    let (cli, srv) = paired();
    cli.send(b"hello duplex").unwrap();
    let got = srv.receive().unwrap();
    assert_eq!(got, b"hello duplex");
    srv.send(b"ack").unwrap();
    assert_eq!(cli.receive().unwrap(), b"ack");
    let _ = srv.close();
    assert!(cli.receive().is_err());
    let _ = cli.close();
}

#[test]
fn concurrent_echo() {
    let (cli, srv) = paired();
    let echo = thread::spawn(move || {
        for _ in 0..50 {
            let b = srv.receive().unwrap();
            srv.send(&b).unwrap();
        }
        let _ = srv.close();
    });
    for i in 0u8..50 {
        cli.send(&[i]).unwrap();
        let out = cli.receive().unwrap();
        assert_eq!(out, vec![i]);
    }
    echo.join().unwrap();
    let _ = cli.close();
}

#[test]
fn unsupported_protocol_version() {
    let mut cfg = Config::default_config();
    cfg.protocol_version = 42;
    let err = match dial_with_config("127.0.0.1:1", Some(&cfg)) {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert!(matches!(err, Error::UnsupportedProtocol));
}

#[test]
fn psk_handshake() {
    let mut cfg = Config::default_config();
    cfg.handshake = HandshakeAuth {
        pre_shared_key: b"unit-test-psk".to_vec(),
        expected_peer_pub_key_sha256: None,
    };

    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let cfg_s = cfg.clone();
    let handle = thread::spawn(move || {
        let (s, _) = ln.accept().unwrap();
        let srv = rutcpduplex::serve_conn_with_config(s, Some(&cfg_s)).unwrap();
        let msg = srv.receive().unwrap();
        assert_eq!(msg, b"ping");
        srv.send(b"pong").unwrap();
        let _ = srv.close();
    });

    let cli = dial_with_config(&addr.to_string(), Some(&cfg)).unwrap();
    cli.send(b"ping").unwrap();
    assert_eq!(cli.receive().unwrap(), b"pong");
    let _ = cli.close();
    handle.join().unwrap();
}

#[test]
fn peer_close_eof() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let done = thread::spawn(move || {
        let (s, _) = ln.accept().unwrap();
        let srv = serve_conn(s).unwrap();
        let _ = srv.close();
    });
    let cli = dial(&addr.to_string()).unwrap();
    done.join().unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(cli.receive().is_err());
    let _ = cli.close();
}

#[test]
fn transfer_blob() {
    let (cli, srv) = paired();
    let payload = b"abcdefgh".repeat(8 << 10);
    let opts = Options {
        chunk_size: 16 << 10,
        window: 4,
        ack_every: 2,
        ..Options::default_options()
    };
    let dst = Arc::new(MemFile::new());
    let dst2 = dst.clone();
    let opts_r = opts.clone();
    let recv = thread::spawn(move || receive_mem(srv, &*dst2, 0, Some(&opts_r)));
    send_bytes(cli, &payload, "blob", Some(&opts)).unwrap();
    recv.join().unwrap().unwrap();
    assert_eq!(dst.bytes(), payload);
}

#[test]
fn transfer_empty() {
    let (cli, srv) = paired();
    let dst = Arc::new(MemFile::new());
    let dst2 = dst.clone();
    let recv = thread::spawn(move || receive_mem(srv, &*dst2, 0, None));
    send_bytes(cli, b"", "empty", None).unwrap();
    recv.join().unwrap().unwrap();
    assert!(dst.is_empty());
}

#[test]
fn transfer_reject() {
    let (cli, srv) = paired();
    let opts = Options {
        accept: Some(Arc::new(|_| Err("denied".into()))),
        ..Options::default_options()
    };
    let dst = MemFile::new();
    let recv = thread::spawn(move || receive_mem(srv, &dst, 0, Some(&opts)));
    let err = send_bytes(cli, b"hi", "x", None).unwrap_err();
    assert!(matches!(
        err,
        rutcpduplex::transfer::TransferError::Rejected
            | rutcpduplex::transfer::TransferError::RejectedReason(_)
    ));
    let _ = recv.join().unwrap();
}
