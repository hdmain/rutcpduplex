//! Cryptographic handshake and AES-GCM session compatible with Go `tcpduplex/crypto`.

mod handshake;
mod session;

pub use handshake::{
    client_handshake, server_handshake, HandshakeError, HandshakeOpts,
    ErrHandshakeAuthenticationFailed, ErrPeerFingerprintMismatch,
};
pub use session::Session;
