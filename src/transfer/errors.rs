//! Transfer sentinel errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("transfer: invalid frame")]
    BadFrame,
    #[error("transfer: offer rejected")]
    Rejected,
    #[error("transfer: offer rejected: {0}")]
    RejectedReason(String),
    #[error("transfer: aborted by peer")]
    Aborted,
    #[error("transfer: aborted by peer: {0}")]
    AbortedReason(String),
    #[error("transfer: size mismatch")]
    SizeMismatch,
    #[error("transfer: content hash mismatch")]
    HashMismatch,
    #[error("transfer: resume offset exceeds size")]
    ResumePastEnd,
    #[error("transfer: connection closed during transfer")]
    Closed,
    #[error("transfer: exceeded MaxAttempts")]
    TooManyRetries,
    #[error("transfer: exceeded MaxAttempts: {0}")]
    TooManyRetriesCause(String),
    #[error("transfer: redial: {0}")]
    Redial(String),
    #[error("transfer: {0}")]
    Other(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Clone for TransferError {
    fn clone(&self) -> Self {
        match self {
            Self::BadFrame => Self::BadFrame,
            Self::Rejected => Self::Rejected,
            Self::RejectedReason(s) => Self::RejectedReason(s.clone()),
            Self::Aborted => Self::Aborted,
            Self::AbortedReason(s) => Self::AbortedReason(s.clone()),
            Self::SizeMismatch => Self::SizeMismatch,
            Self::HashMismatch => Self::HashMismatch,
            Self::ResumePastEnd => Self::ResumePastEnd,
            Self::Closed => Self::Closed,
            Self::TooManyRetries => Self::TooManyRetries,
            Self::TooManyRetriesCause(s) => Self::TooManyRetriesCause(s.clone()),
            Self::Redial(s) => Self::Redial(s.clone()),
            Self::Other(s) => Self::Other(s.clone()),
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind(), e.to_string())),
        }
    }
}
