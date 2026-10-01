//! Dial and serve helpers compatible with Go `tcpduplex` dial API.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{freeze_config, handshake_opts, Config, FrozenConfig};
use crate::conn::Conn;
use crate::crypto;
use crate::errors::{Error, Result};
use crate::protocol;

/// Dial TCP and negotiate a tcpduplex session with default config.
pub fn dial(address: &str) -> Result<Arc<Conn>> {
    dial_with_config(address, None)
}

/// Dial with an optional [`Config`].
pub fn dial_with_config(address: &str, cfg: Option<&Config>) -> Result<Arc<Conn>> {
    let fc = freeze_config(cfg);
    if !protocol::supports_version(fc.protocol_version) {
        return Err(Error::UnsupportedProtocol);
    }

    let mut stream = tcp_connect(address, fc.dial_timeout)?;
    let sess = client_handshake(&mut stream, &fc)?;
    Ok(Conn::new(stream, sess, fc))
}

/// Complete the listener-side handshake on an accepted TCP stream.
pub fn serve_conn(stream: TcpStream) -> Result<Arc<Conn>> {
    serve_conn_with_config(stream, None)
}

/// Listener handshake with optional [`Config`].
pub fn serve_conn_with_config(mut stream: TcpStream, cfg: Option<&Config>) -> Result<Arc<Conn>> {
    let fc = freeze_config(cfg);
    let sess = server_handshake(&mut stream, &fc)?;
    Ok(Conn::new(stream, sess, fc))
}

fn tcp_connect(address: &str, timeout: Duration) -> Result<TcpStream> {
    let addrs: Vec<_> = address
        .to_socket_addrs()
        .map_err(|e| Error::wrap("dial", e))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::Other(format!("dial: no addresses for {address}")));
    }
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    for addr in addrs {
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remain) {
            Ok(s) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(Error::wrap(
        "dial",
        last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout")
        }),
    ))
}

fn apply_handshake_timeout(stream: &TcpStream, timeout: Duration) {
    if !timeout.is_zero() {
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
    }
}

fn clear_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
}

fn client_handshake(stream: &mut TcpStream, fc: &FrozenConfig) -> Result<crypto::Session> {
    apply_handshake_timeout(stream, fc.handshake_timeout);
    let opts = handshake_opts(fc);
    let result = crypto::client_handshake(stream, fc.protocol_version, opts.as_ref());
    clear_timeouts(stream);
    result.map_err(|e| Error::wrap("handshake", e))
}

fn server_handshake(stream: &mut TcpStream, fc: &FrozenConfig) -> Result<crypto::Session> {
    apply_handshake_timeout(stream, fc.handshake_timeout);
    let opts = handshake_opts(fc);
    let result = crypto::server_handshake(stream, opts.as_ref());
    clear_timeouts(stream);
    result
        .map(|(sess, _)| sess)
        .map_err(|e| Error::wrap("handshake", e))
}

// Ensure Read+Write bounds used by crypto are satisfied for TcpStream refs.
#[allow(dead_code)]
fn _assert_rw(s: &mut TcpStream) {
    let _ = s as &mut dyn Read;
    let _ = s as &mut dyn Write;
}
