//! Wire framing and versioning compatible with Go `tcpduplex/protocol`.

use std::io::{self, Read, Write};

use thiserror::Error;

/// Message types carried in the cleartext type byte (outside the ciphertext).
pub const MSG_TEXT: u8 = 1;
pub const MSG_PING: u8 = 2;
pub const MSG_PONG: u8 = 3;
pub const MSG_CLOSE: u8 = 4;

const HANDSHAKE_MAGIC: &[u8; 4] = b"TDX1";

/// Preferred protocol revision negotiated first by library implementations.
pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

/// Encoded length of an X25519 public key on the wire.
pub const X25519_PUB_KEY_LEN: usize = 32;

/// Maximum value of `(1 + sealed.len())` on the wire.
pub const MAX_RECORD_PAYLOAD: u32 = 1 << 20;

/// Protocol-layer errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("protocol: invalid handshake")]
    BadHandshake,
    #[error("protocol: invalid frame")]
    BadFrame,
    #[error("protocol: unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("protocol: i/o error: {0}")]
    Io(String),
}

impl From<io::Error> for ProtocolError {
    fn from(err: io::Error) -> Self {
        ProtocolError::Io(err.to_string())
    }
}

/// Reports whether `v` may be used as the negotiated wire revision.
pub fn supports_version(v: u16) -> bool {
    matches!(v, 1)
}

fn validate_version(v: u16) -> Result<(), ProtocolError> {
    if supports_version(v) {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion(v))
    }
}

fn read_exact_into(r: &mut impl Read, buf: &mut [u8]) -> Result<(), ProtocolError> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ProtocolError::Io(e.to_string())
        } else {
            ProtocolError::from(e)
        }
    })
}

/// Writes magic || negotiated protocol version || X25519 public key.
pub fn write_handshake(
    w: &mut impl Write,
    negotiated_version: u16,
    pub_key: &[u8],
) -> Result<(), ProtocolError> {
    validate_version(negotiated_version)?;
    if pub_key.len() != X25519_PUB_KEY_LEN {
        return Err(ProtocolError::BadHandshake);
    }
    let mut hdr = [0u8; 6];
    hdr[..4].copy_from_slice(HANDSHAKE_MAGIC);
    hdr[4..6].copy_from_slice(&negotiated_version.to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(pub_key)?;
    Ok(())
}

/// Reads and validates magic + declared peer protocol revision + public key.
pub fn read_handshake(r: &mut impl Read) -> Result<(u16, [u8; X25519_PUB_KEY_LEN]), ProtocolError> {
    let mut magic = [0u8; 4];
    read_exact_into(r, &mut magic)?;
    if &magic != HANDSHAKE_MAGIC {
        return Err(ProtocolError::BadHandshake);
    }
    let mut ver = [0u8; 2];
    read_exact_into(r, &mut ver)?;
    let protocol_version = u16::from_be_bytes(ver);
    validate_version(protocol_version)?;
    let mut pub_key = [0u8; X25519_PUB_KEY_LEN];
    read_exact_into(r, &mut pub_key)?;
    Ok((protocol_version, pub_key))
}

/// Reads length || type || sealed (nonce||ciphertext||tag).
pub fn read_record(r: &mut impl Read) -> Result<(u8, Vec<u8>), ProtocolError> {
    let mut len_buf = [0u8; 4];
    read_exact_into(r, &mut len_buf)?;
    let n = u32::from_be_bytes(len_buf);
    if n == 0 || n > MAX_RECORD_PAYLOAD {
        return Err(ProtocolError::BadFrame);
    }
    let mut payload = vec![0u8; n as usize];
    read_exact_into(r, &mut payload)?;
    let msg_type = payload[0];
    let sealed = payload[1..].to_vec();
    Ok((msg_type, sealed))
}

/// Writes length || type || sealed.
pub fn write_record(w: &mut impl Write, msg_type: u8, sealed: &[u8]) -> Result<(), ProtocolError> {
    if sealed.len() > (MAX_RECORD_PAYLOAD as usize) - 1 {
        return Err(ProtocolError::BadFrame);
    }
    let n = (1 + sealed.len()) as u32;
    w.write_all(&n.to_be_bytes())?;
    w.write_all(&[msg_type])?;
    w.write_all(sealed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn handshake_roundtrip() {
        let mut buf = Vec::new();
        let pub_key = [7u8; 32];
        write_handshake(&mut buf, 1, &pub_key).unwrap();
        let (ver, key) = read_handshake(&mut Cursor::new(buf)).unwrap();
        assert_eq!(ver, 1);
        assert_eq!(key, pub_key);
    }

    #[test]
    fn record_roundtrip() {
        let mut buf = Vec::new();
        let sealed = b"nonce||ct||tag".to_vec();
        write_record(&mut buf, MSG_TEXT, &sealed).unwrap();
        let (ty, got) = read_record(&mut Cursor::new(buf)).unwrap();
        assert_eq!(ty, MSG_TEXT);
        assert_eq!(got, sealed);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bad = b"XXXX".to_vec();
        bad.extend_from_slice(&1u16.to_be_bytes());
        bad.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            read_handshake(&mut Cursor::new(bad)),
            Err(ProtocolError::BadHandshake)
        ));
    }
}
