//! X25519 ECDH handshake compatible with Go `tcpduplex/crypto`.

use std::io::{Read, Write};

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::{self, ProtocolError};

use super::session::{new_session, Session};

/// Returned when `ExpectedPeerPubKeySHA256` does not match the peer handshake key.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("crypto: peer public key fingerprint mismatch")]
pub struct ErrPeerFingerprintMismatch;

/// Handshake-layer failures attributable to optional auth constraints.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("crypto: handshake authentication failed")]
pub struct ErrHandshakeAuthenticationFailed;

/// Configures optional authenticated ECDH handshakes.
#[derive(Clone, Default)]
pub struct HandshakeOpts {
    /// Mixed into AEAD session key derivation alongside ECDH output when non-empty.
    pub pre_shared_key: Vec<u8>,
    /// When set, must equal `SHA256(raw X25519 public key bytes)` received from the peer.
    pub expected_peer_pub_key_sha256: Option<[u8; 32]>,
}

fn fingerprint_sha256(pub_key: &[u8]) -> [u8; 32] {
    let sum = Sha256::digest(pub_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sum);
    out
}

fn verify_peer_fingerprint(
    remote_pub: &[u8],
    expected: &Option<[u8; 32]>,
) -> Result<(), ErrPeerFingerprintMismatch> {
    if let Some(exp) = expected {
        let sum = fingerprint_sha256(remote_pub);
        if &sum != exp {
            return Err(ErrPeerFingerprintMismatch);
        }
    }
    Ok(())
}

/// Completes the tcpduplex handshake from the initiator side.
pub fn client_handshake(
    rw: &mut (impl Read + Write),
    negotiated_version: u16,
    opts: Option<&HandshakeOpts>,
) -> Result<Session, HandshakeError> {
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = PublicKey::from(&priv_key);
    protocol::write_handshake(rw, negotiated_version, pub_key.as_bytes())?;

    let (peer_ver, peer_pub_bytes) = protocol::read_handshake(rw)?;
    if peer_ver != negotiated_version {
        return Err(HandshakeError::Auth(ErrHandshakeAuthenticationFailed));
    }
    if let Some(o) = opts {
        verify_peer_fingerprint(&peer_pub_bytes, &o.expected_peer_pub_key_sha256)?;
    }

    let remote_pub = PublicKey::from(peer_pub_bytes);
    let shared = priv_key.diffie_hellman(&remote_pub);
    let psk = opts.map(|o| o.pre_shared_key.as_slice()).unwrap_or(&[]);
    Ok(new_session(shared.as_bytes(), psk)?)
}

/// Completes the tcpduplex handshake from the listener side.
pub fn server_handshake(
    rw: &mut (impl Read + Write),
    opts: Option<&HandshakeOpts>,
) -> Result<(Session, u16), HandshakeError> {
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = PublicKey::from(&priv_key);

    let (peer_ver, peer_pub_bytes) = protocol::read_handshake(rw)?;
    if let Some(o) = opts {
        verify_peer_fingerprint(&peer_pub_bytes, &o.expected_peer_pub_key_sha256)?;
    }

    let remote_pub = PublicKey::from(peer_pub_bytes);
    let shared = priv_key.diffie_hellman(&remote_pub);

    protocol::write_handshake(rw, peer_ver, pub_key.as_bytes())?;

    let psk = opts.map(|o| o.pre_shared_key.as_slice()).unwrap_or(&[]);
    let sess = new_session(shared.as_bytes(), psk)?;
    Ok((sess, peer_ver))
}

/// Errors from the handshake layer.
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Fingerprint(#[from] ErrPeerFingerprintMismatch),
    #[error(transparent)]
    Auth(ErrHandshakeAuthenticationFailed),
}
