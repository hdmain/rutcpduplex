//! Chat-style server using `Server::listen` + `serve`.

use std::env;
use std::io::{self, BufRead};
use std::sync::{Arc, Mutex};
use std::thread;

use rutcpduplex::{Conn, Server};

fn main() {
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:9090".into());
    let srv = Server::listen(&*addr, None).expect("listen");
    println!("rutcpduplex listening on {}", srv.addr().unwrap());

    let peers: Arc<Mutex<Vec<Arc<Conn>>>> = Arc::new(Mutex::new(Vec::new()));
    let peers_stdin = peers.clone();

    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            let guard = peers_stdin.lock().unwrap();
            for c in guard.iter() {
                let _ = c.send(line.as_bytes());
            }
        }
    });

    let peers_serve = peers.clone();
    let _ = srv.serve(move |conn| {
        if let Ok(addr) = conn.peer_addr() {
            eprintln!("peer joined: {addr}");
        }
        {
            peers_serve.lock().unwrap().push(conn.clone());
        }
        loop {
            match conn.receive() {
                Ok(msg) => {
                    let line = format!(
                        "[{}] {}",
                        conn.peer_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "?".into()),
                        String::from_utf8_lossy(&msg)
                    );
                    eprintln!("{line}");
                    let guard = peers_serve.lock().unwrap();
                    for c in guard.iter() {
                        let _ = c.send(line.as_bytes());
                    }
                }
                Err(_) => break,
            }
        }
        let mut guard = peers_serve.lock().unwrap();
        guard.retain(|c| !Arc::ptr_eq(c, &conn));
        let _ = conn.close();
    });
}
