//! Wire frames carried inside MsgText (magic + type + payload).

use super::errors::TransferError;
use super::id::TransferId;

pub(crate) const TYPE_OFFER: u8 = 1;
pub(crate) const TYPE_ACCEPT: u8 = 2;
pub(crate) const TYPE_REJECT: u8 = 3;
pub(crate) const TYPE_CHUNK: u8 = 4;
pub(crate) const TYPE_ACK: u8 = 5;
pub(crate) const TYPE_DONE: u8 = 6;
pub(crate) const TYPE_ABORT: u8 = 7;

pub(crate) const FRAME_MAGIC: [u8; 4] = *b"TFX1";

pub(crate) const HEADER_LEN: usize = 5;
pub(crate) const ID_LEN: usize = 16;
pub(crate) const OFFER_FIXED_LEN: usize = HEADER_LEN + ID_LEN + 8 + 32 + 2;
pub(crate) const ACCEPT_LEN: usize = HEADER_LEN + ID_LEN + 8;
pub(crate) const CHUNK_FIXED_LEN: usize = HEADER_LEN + ID_LEN + 8;
pub(crate) const ACK_LEN: usize = HEADER_LEN + ID_LEN + 8;
pub(crate) const DONE_LEN: usize = HEADER_LEN + ID_LEN + 1 + 32;
pub(crate) const REJECT_FIXED_LEN: usize = HEADER_LEN + ID_LEN + 2;
pub(crate) const ABORT_FIXED_LEN: usize = HEADER_LEN + ID_LEN + 2;

/// Describes a file/stream being offered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub id: TransferId,
    pub name: String,
    pub size: i64,
    /// SHA-256 of complete content. Zero means sender did not supply a hash.
    pub hash: [u8; 32],
}

pub(crate) fn encode_offer(m: &Meta) -> Result<Vec<u8>, TransferError> {
    if m.size < 0 {
        return Err(TransferError::SizeMismatch);
    }
    if !m.name.is_ascii() && std::str::from_utf8(m.name.as_bytes()).is_err() {
        return Err(TransferError::BadFrame);
    }
    // UTF-8 validity: Rust String is always UTF-8.
    let name = m.name.as_bytes();
    if name.len() > 0xffff {
        return Err(TransferError::BadFrame);
    }
    let mut buf = vec![0u8; OFFER_FIXED_LEN + name.len()];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_OFFER;
    buf[5..21].copy_from_slice(&m.id.0);
    buf[21..29].copy_from_slice(&(m.size as u64).to_be_bytes());
    buf[29..61].copy_from_slice(&m.hash);
    buf[61..63].copy_from_slice(&(name.len() as u16).to_be_bytes());
    buf[63..].copy_from_slice(name);
    Ok(buf)
}

pub(crate) fn encode_accept(id: TransferId, resume_offset: i64) -> Vec<u8> {
    let mut buf = vec![0u8; ACCEPT_LEN];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_ACCEPT;
    buf[5..21].copy_from_slice(&id.0);
    buf[21..29].copy_from_slice(&(resume_offset as u64).to_be_bytes());
    buf
}

pub(crate) fn encode_reject(id: TransferId, reason: &str) -> Vec<u8> {
    let mut r = reason.as_bytes();
    if r.len() > 0xffff {
        r = &r[..0xffff];
    }
    let mut buf = vec![0u8; REJECT_FIXED_LEN + r.len()];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_REJECT;
    buf[5..21].copy_from_slice(&id.0);
    buf[21..23].copy_from_slice(&(r.len() as u16).to_be_bytes());
    buf[23..].copy_from_slice(r);
    buf
}

pub(crate) fn encode_chunk(id: TransferId, offset: i64, data: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; CHUNK_FIXED_LEN + data.len()];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_CHUNK;
    buf[5..21].copy_from_slice(&id.0);
    buf[21..29].copy_from_slice(&(offset as u64).to_be_bytes());
    buf[29..].copy_from_slice(data);
    buf
}

pub(crate) fn encode_ack(id: TransferId, cum_offset: i64) -> Vec<u8> {
    let mut buf = vec![0u8; ACK_LEN];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_ACK;
    buf[5..21].copy_from_slice(&id.0);
    buf[21..29].copy_from_slice(&(cum_offset as u64).to_be_bytes());
    buf
}

pub(crate) fn encode_done(id: TransferId, ok: bool, hash: [u8; 32]) -> Vec<u8> {
    let mut buf = vec![0u8; DONE_LEN];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_DONE;
    buf[5..21].copy_from_slice(&id.0);
    if ok {
        buf[21] = 1;
    }
    buf[22..54].copy_from_slice(&hash);
    buf
}

pub(crate) fn encode_abort(id: TransferId, reason: &str) -> Vec<u8> {
    let mut r = reason.as_bytes();
    if r.len() > 0xffff {
        r = &r[..0xffff];
    }
    let mut buf = vec![0u8; ABORT_FIXED_LEN + r.len()];
    buf[..4].copy_from_slice(&FRAME_MAGIC);
    buf[4] = TYPE_ABORT;
    buf[5..21].copy_from_slice(&id.0);
    buf[21..23].copy_from_slice(&(r.len() as u16).to_be_bytes());
    buf[23..].copy_from_slice(r);
    buf
}

#[derive(Debug)]
pub(crate) struct Decoded {
    pub typ: u8,
    pub id: TransferId,
    pub meta: Meta,
    pub offset: i64,
    pub data: Vec<u8>,
    pub ok: bool,
    pub hash: [u8; 32],
    pub reason: String,
}

pub(crate) fn decode_frame(b: &[u8]) -> Result<Decoded, TransferError> {
    let mut d = Decoded {
        typ: 0,
        id: TransferId::default(),
        meta: Meta::default(),
        offset: 0,
        data: Vec::new(),
        ok: false,
        hash: [0u8; 32],
        reason: String::new(),
    };
    if b.len() < HEADER_LEN {
        return Err(TransferError::BadFrame);
    }
    if b[0..4] != FRAME_MAGIC {
        return Err(TransferError::BadFrame);
    }
    d.typ = b[4];
    match d.typ {
        TYPE_OFFER => {
            if b.len() < OFFER_FIXED_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            d.meta.id = d.id;
            d.meta.size = i64::from_be_bytes(b[21..29].try_into().unwrap());
            d.meta.hash.copy_from_slice(&b[29..61]);
            let nlen = u16::from_be_bytes(b[61..63].try_into().unwrap()) as usize;
            if b.len() != OFFER_FIXED_LEN + nlen {
                return Err(TransferError::BadFrame);
            }
            d.meta.name = String::from_utf8(b[63..].to_vec()).map_err(|_| TransferError::BadFrame)?;
        }
        TYPE_ACCEPT => {
            if b.len() != ACCEPT_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            d.offset = i64::from_be_bytes(b[21..29].try_into().unwrap());
        }
        TYPE_REJECT => {
            if b.len() < REJECT_FIXED_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            let nlen = u16::from_be_bytes(b[21..23].try_into().unwrap()) as usize;
            if b.len() != REJECT_FIXED_LEN + nlen {
                return Err(TransferError::BadFrame);
            }
            d.reason = String::from_utf8_lossy(&b[23..]).into_owned();
        }
        TYPE_CHUNK => {
            if b.len() < CHUNK_FIXED_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            d.offset = i64::from_be_bytes(b[21..29].try_into().unwrap());
            d.data = b[29..].to_vec();
        }
        TYPE_ACK => {
            if b.len() != ACK_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            d.offset = i64::from_be_bytes(b[21..29].try_into().unwrap());
        }
        TYPE_DONE => {
            if b.len() != DONE_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            d.ok = b[21] != 0;
            d.hash.copy_from_slice(&b[22..54]);
        }
        TYPE_ABORT => {
            if b.len() < ABORT_FIXED_LEN {
                return Err(TransferError::BadFrame);
            }
            d.id.0.copy_from_slice(&b[5..21]);
            let nlen = u16::from_be_bytes(b[21..23].try_into().unwrap()) as usize;
            if b.len() != ABORT_FIXED_LEN + nlen {
                return Err(TransferError::BadFrame);
            }
            d.reason = String::from_utf8_lossy(&b[23..]).into_owned();
        }
        _ => return Err(TransferError::BadFrame),
    }
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn frame_roundtrip() {
        let id = TransferId::new().unwrap();
        let hash = Sha256::digest(b"x");
        let mut h = [0u8; 32];
        h.copy_from_slice(&hash);
        let meta = Meta {
            id,
            name: "demo.bin".into(),
            size: 12345,
            hash: h,
        };
        let offer = encode_offer(&meta).unwrap();
        let d = decode_frame(&offer).unwrap();
        assert_eq!(d.typ, TYPE_OFFER);
        assert_eq!(d.meta, meta);

        for frame in [
            encode_accept(id, 99),
            encode_ack(id, 50),
            encode_chunk(id, 10, b"payload"),
            encode_done(id, true, meta.hash),
            encode_reject(id, "nope"),
            encode_abort(id, "stop"),
        ] {
            decode_frame(&frame).unwrap();
        }
    }
}
