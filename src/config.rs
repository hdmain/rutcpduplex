//! Configuration types compatible with Go `tcpduplex.Config`.

use std::sync::Arc;
use std::time::Duration;

use crate::crypto::HandshakeOpts;
use crate::protocol;

const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_MAX_MESSAGE_BYTES: usize = 512 << 10; // 512 KiB
const DEFAULT_SEND_QUEUE_DEPTH: usize = 256;
const DEFAULT_RECEIVE_QUEUE_DEPTH: usize = 256;
const DEFAULT_ON_MESSAGE_BUFFER_DEPTH: usize = 128;

/// Optional authenticated ECDH (PSK mixing + optional peer fingerprint).
#[derive(Clone, Default)]
pub struct HandshakeAuth {
    /// Mixed into the symmetric key derivation alongside ECDH output when non-empty.
    pub pre_shared_key: Vec<u8>,
    /// When set, must equal `SHA256(peer raw X25519 public key bytes)`.
    pub expected_peer_pub_key_sha256: Option<[u8; 32]>,
}

/// Callback type for asynchronous inbound message delivery.
pub type OnMessageFn = Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>;

/// Tunes transport timing, queue depths, protocol revision, and handshake authentication.
#[derive(Clone)]
pub struct Config {
    /// Bounds TCP dial when establishing the connection (zero uses default).
    pub dial_timeout: Duration,
    /// Bounds the ECDH handshake on the wire (zero uses default).
    pub handshake_timeout: Duration,
    /// Wire revision advertised by the client. Must satisfy [`protocol::supports_version`].
    pub protocol_version: u16,
    /// Caps decrypted plaintext application payloads (send + receive).
    pub max_message_bytes: usize,
    /// Bounds the outbound channel (Send backpressure).
    pub send_queue_depth: usize,
    /// Bounds Receive buffering when `on_message` is `None`.
    pub receive_queue_depth: usize,
    /// When set, delivers inbound `MsgText` asynchronously without requiring `Receive`.
    pub on_message: Option<OnMessageFn>,
    /// Bounds pending deliveries waiting for `on_message`.
    pub on_message_buffer_depth: usize,
    /// Tears down the session when `on_message_buffer_depth` is exhausted.
    pub disconnect_on_slow_callback_consumer: bool,
    /// Optional pre-shared key mixing and fingerprint verification.
    pub handshake: HandshakeAuth,
}

impl Default for Config {
    fn default() -> Self {
        Self::default_config()
    }
}

impl Config {
    /// Conservative production defaults (Go `DefaultConfig`).
    pub fn default_config() -> Self {
        Self {
            dial_timeout: DEFAULT_DIAL_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            protocol_version: protocol::CURRENT_PROTOCOL_VERSION,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            send_queue_depth: DEFAULT_SEND_QUEUE_DEPTH,
            receive_queue_depth: DEFAULT_RECEIVE_QUEUE_DEPTH,
            on_message: None,
            on_message_buffer_depth: DEFAULT_ON_MESSAGE_BUFFER_DEPTH,
            disconnect_on_slow_callback_consumer: false,
            handshake: HandshakeAuth::default(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct FrozenConfig {
    pub dial_timeout: Duration,
    pub handshake_timeout: Duration,
    pub protocol_version: u16,
    pub max_message_bytes: usize,
    pub send_queue_depth: usize,
    pub receive_queue_depth: usize,
    pub on_message: Option<OnMessageFn>,
    pub on_message_buffer_depth: usize,
    pub disconnect_on_slow_callback_consumer: bool,
    pub handshake: HandshakeAuth,
}

pub(crate) fn freeze_config(cfg: Option<&Config>) -> FrozenConfig {
    let owned;
    let cfg = match cfg {
        Some(c) => c,
        None => {
            owned = Config::default_config();
            &owned
        }
    };

    let mut f = FrozenConfig {
        dial_timeout: cfg.dial_timeout,
        handshake_timeout: cfg.handshake_timeout,
        protocol_version: cfg.protocol_version,
        max_message_bytes: cfg.max_message_bytes,
        send_queue_depth: cfg.send_queue_depth,
        receive_queue_depth: cfg.receive_queue_depth,
        on_message: cfg.on_message.clone(),
        on_message_buffer_depth: cfg.on_message_buffer_depth,
        disconnect_on_slow_callback_consumer: cfg.disconnect_on_slow_callback_consumer,
        handshake: cfg.handshake.clone(),
    };

    if f.dial_timeout.is_zero() {
        f.dial_timeout = DEFAULT_DIAL_TIMEOUT;
    }
    if f.handshake_timeout.is_zero() {
        f.handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT;
    }
    if f.protocol_version == 0 {
        f.protocol_version = protocol::CURRENT_PROTOCOL_VERSION;
    }
    if f.max_message_bytes == 0 {
        f.max_message_bytes = DEFAULT_MAX_MESSAGE_BYTES;
    }
    if f.send_queue_depth == 0 {
        f.send_queue_depth = DEFAULT_SEND_QUEUE_DEPTH;
    }
    if f.receive_queue_depth == 0 {
        f.receive_queue_depth = DEFAULT_RECEIVE_QUEUE_DEPTH;
    }
    if f.on_message.is_some() && f.on_message_buffer_depth == 0 {
        f.on_message_buffer_depth = DEFAULT_ON_MESSAGE_BUFFER_DEPTH;
    }
    f
}

pub(crate) fn handshake_opts(f: &FrozenConfig) -> Option<HandshakeOpts> {
    if f.handshake.pre_shared_key.is_empty() && f.handshake.expected_peer_pub_key_sha256.is_none() {
        return None;
    }
    Some(HandshakeOpts {
        pre_shared_key: f.handshake.pre_shared_key.clone(),
        expected_peer_pub_key_sha256: f.handshake.expected_peer_pub_key_sha256,
    })
}
