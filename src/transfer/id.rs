//! Transfer ID helpers.

use rand::RngCore;

use super::errors::TransferError;

/// Uniquely identifies a transfer across reconnects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TransferId(pub [u8; 16]);

impl TransferId {
    /// Cryptographically random transfer ID.
    pub fn new() -> Result<Self, TransferError> {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        Ok(Self(id))
    }

    /// 32 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for TransferId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Parses a 32-character hex transfer ID.
pub fn parse_id(s: &str) -> Result<TransferId, TransferError> {
    let b = hex::decode(s).map_err(|_| TransferError::Other(format!("invalid id {s:?}")))?;
    if b.len() != 16 {
        return Err(TransferError::Other(format!("invalid id {s:?}")));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&b);
    Ok(TransferId(id))
}
