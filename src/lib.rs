//! Native Rust port of [tcpduplex](https://github.com/hdmain/tcpduplex):
//! encrypted full-duplex messaging over TCP (X25519 ECDH, AES-256-GCM).
//!
//! Protocol-compatible with the Go library so `Go ↔ Rust` sessions interoperate.
//!
//! # Quick start
//!
//! ```no_run
//! use rutcpduplex::{dial, serve_conn};
//! use std::net::TcpListener;
//! use std::thread;
//!
//! let ln = TcpListener::bind("127.0.0.1:0").unwrap();
//! let addr = ln.local_addr().unwrap();
//! thread::spawn(move || {
//!     let (stream, _) = ln.accept().unwrap();
//!     let srv = serve_conn(stream).unwrap();
//!     let msg = srv.receive().unwrap();
//!     srv.send(&msg).unwrap();
//!     let _ = srv.close();
//! });
//!
//! let cli = dial(&addr.to_string()).unwrap();
//! cli.send(b"hello").unwrap();
//! let out = cli.receive().unwrap();
//! assert_eq!(out, b"hello");
//! let _ = cli.close();
//! ```

pub mod crypto;
pub mod protocol;
pub mod transfer;

mod config;
mod conn;
mod dial;
mod errors;
mod fingerprint;
mod server;

pub use config::{Config, HandshakeAuth, OnMessageFn};
pub use conn::Conn;
pub use dial::{dial, dial_with_config, serve_conn, serve_conn_with_config};
pub use errors::{Error, Result};
pub use fingerprint::peer_public_key_fingerprint;
pub use server::Server;

/// Library version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
