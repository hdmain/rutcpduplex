# rutcpduplex

Native **Rust** port of [`tcpduplex`](https://github.com/hdmain/tcpduplex): encrypted full-duplex messaging over TCP using X25519 ECDH, AES-256-GCM, length-prefixed records, and concurrent read/write loops.

This is **not** TLS and does not replace certificate-based authentication on the public internet. It suits private networks, constrained environments, or protocols where you control both peers.

## Other languages

Wire-compatible ports of the same protocol:

| Language | Repository |
|----------|------------|
| Go | [tcpduplex](https://github.com/hdmain/tcpduplex) |
| Kotlin / Android | [tcpduplexkt](https://github.com/hdmain/tcpduplexkt) |
| C++20 | [cpptcpduplex](https://github.com/hdmain/cpptcpduplex) |
| Rust (this repo) | [rutcpduplex](https://github.com/hdmain/rutcpduplex) |

## Requirements

- Rust **1.75+** (edition 2021)
- Optional: Go **1.22+** for Go ↔ Rust interoperability tests

## Install

```bash
cargo add rutcpduplex
```

Or in `Cargo.toml`:

```toml
[dependencies]
rutcpduplex = "0.1"
```

## Features

- Duplex `Conn` with `send` / `receive`, bounded queues, max message size
- Optional `on_message` callback delivery path
- `Config`: dial/handshake timeouts, protocol version, queue depths, PSK + peer fingerprint hooks
- `Server`: `listen` + `serve` with per-connection handler
- Submodules `protocol` (framing), `crypto` (handshake + AES-GCM), `transfer` (encrypted resumable file transfers)

## Quick start

### Client

```rust
use rutcpduplex::dial;

let conn = dial("127.0.0.1:9090")?;
conn.send(b"hello")?;
let msg = conn.receive()?;
println!("got: {}", String::from_utf8_lossy(&msg));
conn.close()?;
```

### Server (manual accept)

```rust
use std::net::TcpListener;
use rutcpduplex::serve_conn;

let ln = TcpListener::bind("127.0.0.1:9090")?;
let (stream, _) = ln.accept()?;
let conn = serve_conn(stream)?;
let msg = conn.receive()?;
conn.send(&msg)?;
conn.close()?;
```

### Server helper

```rust
use rutcpduplex::Server;

let srv = Server::listen("127.0.0.1:9090", None)?;
srv.serve(|conn| {
    if let Ok(msg) = conn.receive() {
        let _ = conn.send(&msg);
    }
    let _ = conn.close();
})?;
```

### PSK

```rust
use rutcpduplex::{dial_with_config, Config, HandshakeAuth};

let mut cfg = Config::default_config();
cfg.handshake = HandshakeAuth {
    pre_shared_key: b"rotate-this-secret".to_vec(),
    expected_peer_pub_key_sha256: None,
};
let conn = dial_with_config("127.0.0.1:9090", Some(&cfg))?;
```

## Encrypted file transfer

```rust
use rutcpduplex::transfer::{send_file, receive_file, Options};
use std::sync::Arc;

// sender
send_file(conn.clone(), "/path/to/file", Some(&Options {
    chunk_size: 256 << 10,
    window: 32,
    ..Options::default_options()
}))?;

// receiver
let meta = receive_file(conn, "/path/to/dest", None)?;
```

While a transfer is running, do not use the same `Conn` for other `send`/`receive` traffic (frames share `MsgText`).

## Wire format (summary)

1. **Handshake (plaintext)** — Magic `TDX1`, `uint16` BE protocol version, 32-byte X25519 public key. Client sends first; server replies with the same negotiated version and its public key.
2. **Records** — `uint32` BE length (includes 1-byte type + sealed blob), type byte (`MsgText`, `MsgPing`, `MsgPong`, `MsgClose`), then `nonce ‖ ciphertext ‖ tag` from AES-256-GCM.

Key derivation matches Go `tcpduplex`:

- No PSK: `SHA256(shared_secret)`
- With PSK: `SHA256(shared_secret ‖ 0x00 ‖ len(psk) BE ‖ psk)`

## Examples

```bash
cargo run --example simple
cargo run --example transfer
cargo run --example server -- 127.0.0.1:9090
cargo run --example client -- 127.0.0.1:9090
```

## Building and testing

```bash
cargo build --release
cargo test
```

Go ↔ Rust compatibility tests (requires Go toolchain):

```bash
cargo test --test go_compat_tests
```

## Project structure

```
rutcpduplex/
├── src/
│   ├── lib.rs          # crate root
│   ├── config.rs       # Config / HandshakeAuth
│   ├── conn.rs         # duplex Conn
│   ├── dial.rs         # dial / serve_conn
│   ├── server.rs       # Server helper
│   ├── errors.rs
│   ├── fingerprint.rs
│   ├── protocol/       # framing + versioning
│   ├── crypto/         # ECDH handshake + AES-GCM session
│   └── transfer/       # resumable encrypted transfers
├── examples/
├── tests/
│   ├── integration.rs
│   ├── go_compat_tests.rs
│   └── go_compat/      # Go peer helper
├── Cargo.toml
├── LICENSE
└── README.md
```

## Security notes

- Symmetric keys derive from ECDH; with `pre_shared_key`, material is mixed on both sides — peers must agree on the secret.
- Fingerprint pinning checks the peer’s ephemeral X25519 public key from the handshake (not a long-term identity certificate).
- For authentication + integrity + PKI on hostile networks, prefer TLS (or QUIC).

## License

MIT — same family of licensing as other [hdmain](https://github.com/hdmain) projects. The original Go `tcpduplex` repository did not include a `LICENSE` file at the time of this port; this crate is published under the MIT License.

## See also

- Go library: https://github.com/hdmain/tcpduplex
