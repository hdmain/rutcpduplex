//! AES-256-GCM session derived from ECDH (optionally mixed with PSK).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::protocol::{ProtocolError, MAX_RECORD_PAYLOAD};

/// Holds AES-GCM state derived from ECDH (optionally mixed with PSK material).
pub struct Session {
    gcm: Aes256Gcm,
}

pub(crate) fn derive_session_key(shared_secret: &[u8], psk: &[u8]) -> [u8; 32] {
    if psk.is_empty() {
        let sum = Sha256::digest(shared_secret);
        let mut out = [0u8; 32];
        out.copy_from_slice(&sum);
        return out;
    }
    let mut h = Sha256::new();
    h.update(shared_secret);
    h.update([0u8]);
    h.update(&(psk.len() as u32).to_be_bytes());
    h.update(psk);
    let sum = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&sum);
    out
}

pub(crate) fn new_session(shared_secret: &[u8], psk: &[u8]) -> Result<Session, ProtocolError> {
    let key = derive_session_key(shared_secret, psk);
    let gcm = Aes256Gcm::new_from_slice(&key).map_err(|_| ProtocolError::BadFrame)?;
    Ok(Session { gcm })
}

impl Session {
    /// Encrypts plaintext and returns `nonce || ciphertext || tag`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        const NONCE_SIZE: usize = 12;
        const TAG_SIZE: usize = 16;
        let max_seal = (MAX_RECORD_PAYLOAD as usize) - 1;
        if NONCE_SIZE + TAG_SIZE + plaintext.len() > max_seal {
            return Err(ProtocolError::BadFrame);
        }
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .gcm
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| ProtocolError::BadFrame)?;
        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts a blob produced by [`Session::seal`].
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        const NONCE_SIZE: usize = 12;
        const TAG_SIZE: usize = 16;
        if sealed.len() < NONCE_SIZE + TAG_SIZE {
            return Err(ProtocolError::BadFrame);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.gcm
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: b"",
                },
            )
            .map_err(|_| ProtocolError::BadFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let sess = new_session(b"shared-secret-32-bytes!!!!!!!!!!", b"").unwrap();
        let pt = b"hello world";
        let sealed = sess.seal(pt).unwrap();
        let out = sess.open(&sealed).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn psk_changes_key() {
        let a = derive_session_key(b"shared", b"");
        let b = derive_session_key(b"shared", b"psk");
        assert_ne!(a, b);
    }
}
