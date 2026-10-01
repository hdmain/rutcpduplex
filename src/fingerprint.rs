//! Peer public-key fingerprint helper.

use sha2::{Digest, Sha256};

/// Returns `SHA256(raw X25519 public key bytes)` for use with
/// [`HandshakeAuth::expected_peer_pub_key_sha256`](crate::HandshakeAuth::expected_peer_pub_key_sha256).
pub fn peer_public_key_fingerprint(pub_key: &[u8]) -> [u8; 32] {
    let sum = Sha256::digest(pub_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sum);
    out
}
