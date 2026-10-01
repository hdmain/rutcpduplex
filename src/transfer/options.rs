//! Transfer options.

use std::sync::Arc;

use crate::conn::Conn;

use super::frame::Meta;

const DEFAULT_CHUNK_SIZE: usize = 256 << 10;
const DEFAULT_WINDOW: usize = 32;
const DEFAULT_ACK_EVERY: usize = 8;
const DEFAULT_ATTEMPTS: usize = 8;

pub(crate) const CHUNK_OVERHEAD: usize = 5 + 16 + 8; // magic+type+id+offset

/// Callback to obtain a fresh connection after a failure.
pub type RedialFn = Arc<dyn Fn() -> Result<std::sync::Arc<Conn>, String> + Send + Sync>;

/// Tunes throughput, resume, and reconnect behavior.
#[derive(Clone, Default)]
pub struct Options {
    pub chunk_size: usize,
    pub window: usize,
    pub ack_every: usize,
    pub redial: Option<RedialFn>,
    pub max_attempts: usize,
    pub on_progress: Option<Arc<dyn Fn(i64, i64) + Send + Sync>>,
    pub accept: Option<Arc<dyn Fn(&Meta) -> Result<(), String> + Send + Sync>>,
}

/// Alias for clarity in docs.
pub type DefaultOptions = Options;

impl Options {
    pub fn default_options() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            window: DEFAULT_WINDOW,
            ack_every: DEFAULT_ACK_EVERY,
            redial: None,
            max_attempts: DEFAULT_ATTEMPTS,
            on_progress: None,
            accept: None,
        }
    }
}

pub(crate) fn normalize_options(opts: Option<&Options>) -> Options {
    let d = Options::default_options();
    let Some(opts) = opts else {
        return d;
    };
    let mut out = opts.clone();
    if out.chunk_size == 0 {
        out.chunk_size = d.chunk_size;
    }
    if out.window == 0 {
        out.window = d.window;
    }
    if out.ack_every == 0 {
        out.ack_every = d.ack_every;
    }
    if out.max_attempts == 0 {
        out.max_attempts = d.max_attempts;
    }
    out
}

pub(crate) fn effective_chunk_size(conn: &Conn, want: usize) -> usize {
    let mut max = conn.max_message_bytes().saturating_sub(CHUNK_OVERHEAD);
    if max < 1 {
        max = 1;
    }
    if want == 0 || want > max {
        max
    } else {
        want
    }
}
