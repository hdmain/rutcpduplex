//! Line-oriented client example.

use std::env;
use std::io::{self, BufRead, Write};
use std::thread;

use rutcpduplex::dial;

fn main() {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9090".into());

    let conn = dial(&addr).expect("dial");
    println!("connected to {addr}");

    let reader = conn.clone();
    thread::spawn(move || loop {
        match reader.receive() {
            Ok(msg) => println!("{}", String::from_utf8_lossy(&msg)),
            Err(_) => break,
        }
    });

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        if line == "/quit" {
            break;
        }
        if let Err(e) = conn.send(line.as_bytes()) {
            eprintln!("send: {e}");
            break;
        }
        let _ = io::stdout().flush();
    }
    let _ = conn.close();
}
