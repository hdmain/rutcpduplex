//! Public error types mirroring Go `tcpduplex` sentinels.

use std::io;

use thiserror::Error;

use crate::crypto::{ErrHandshakeAuthenticationFailed, ErrPeerFingerprintMismatch};
use crate::protocol::ProtocolError;

/// Connection / dial sentinel errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("tcpduplex: connection closed")]
    Closed,

    #[error("tcpduplex: Receive unavailable while OnMessage is configured")]
    ReceiveDisabled,

    #[error("tcpduplex: message exceeds MaxMessageBytes")]
    MessageTooLarge,

    #[error("tcpduplex: inbound OnMessage buffer full")]
    InboundDropped,

    #[error("tcpduplex: disconnected due to slow OnMessage consumer")]
    SlowConsumer,

    #[error("protocol: unsupported protocol version")]
    UnsupportedProtocol,

    #[error("crypto: handshake authentication failed")]
    HandshakeAuthentication,

    #[error("crypto: peer public key fingerprint mismatch")]
    PeerFingerprintMismatch,

    #[error("tcpduplex: end of stream")]
    Eof,

    #[error("tcpduplex {op}: {source}")]
    Op {
        op: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("tcpduplex: {0}")]
    Other(String),
}

impl Error {
    /// Wraps `err` with an operation name (Go `Wrap`).
    pub fn wrap(op: &'static str, err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Error::Op {
            op,
            source: err.into(),
        }
    }

    /// True when this error (or its source chain) is [`Error::Closed`].
    pub fn is_closed(&self) -> bool {
        matches!(self, Error::Closed)
            || matches!(self, Error::Op { source, .. } if source.to_string().contains("connection closed"))
    }
}

impl From<ErrPeerFingerprintMismatch> for Error {
    fn from(_: ErrPeerFingerprintMismatch) -> Self {
        Error::PeerFingerprintMismatch
    }
}

impl From<ErrHandshakeAuthenticationFailed> for Error {
    fn from(_: ErrHandshakeAuthenticationFailed) -> Self {
        Error::HandshakeAuthentication
    }
}

impl From<crate::crypto::HandshakeError> for Error {
    fn from(err: crate::crypto::HandshakeError) -> Self {
        match err {
            crate::crypto::HandshakeError::Protocol(e) => Error::Protocol(e),
            crate::crypto::HandshakeError::Fingerprint(_) => Error::PeerFingerprintMismatch,
            crate::crypto::HandshakeError::Auth(_) => Error::HandshakeAuthentication,
        }
    }
}

/// Result alias for library operations.
pub type Result<T> = std::result::Result<T, Error>;

