//! Encrypted file transfer example (in-process client + server).

use std::net::TcpListener;
use std::thread;

use rutcpduplex::transfer::{receive_mem, send_bytes, MemFile, Options};
use rutcpduplex::{dial, serve_conn};

fn main() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (stream, _) = ln.accept().unwrap();
        let srv = serve_conn(stream).unwrap();
        let dst = MemFile::new();
        let opts = Options {
            chunk_size: 16 << 10,
            window: 4,
            ack_every: 2,
            ..Options::default_options()
        };
        let meta = receive_mem(srv.clone(), &dst, 0, Some(&opts)).expect("recv");
        println!(
            "received {} ({} bytes)",
            meta.name,
            dst.len()
        );
        let _ = srv.close();
        dst.bytes()
    });

    let payload = b"abcdefgh".repeat(8 << 10); // 64 KiB
    let cli = dial(&addr.to_string()).unwrap();
    let opts = Options {
        chunk_size: 16 << 10,
        window: 4,
        ..Options::default_options()
    };
    send_bytes(cli.clone(), &payload, "blob", Some(&opts)).expect("send");
    let _ = cli.close();

    let got = server.join().unwrap();
    assert_eq!(got, payload);
    println!("transfer ok ({} bytes)", got.len());
}
