//! Minimal listen/dial round-trip example.

use std::net::TcpListener;
use std::thread;

use rutcpduplex::{dial, serve_conn};

fn main() {
    let ln = TcpListener::bind("127.0.0.1:0").expect("listen");
    let addr = ln.local_addr().unwrap();
    println!("listening on {addr}");

    let server = thread::spawn(move || {
        let (stream, _) = ln.accept().expect("accept");
        let srv = serve_conn(stream).expect("handshake");
        let msg = srv.receive().expect("recv");
        println!("server received: {}", String::from_utf8_lossy(&msg));
        srv.send(b"world").expect("send");
        let _ = srv.close();
    });

    let cli = dial(&addr.to_string()).expect("dial");
    cli.send(b"hello").expect("send");
    let out = cli.receive().expect("recv");
    println!("client received: {}", String::from_utf8_lossy(&out));
    let _ = cli.close();
    let _ = server.join();
}
