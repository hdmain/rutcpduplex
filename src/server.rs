//! TCP listener helper compatible with Go `tcpduplex.Server`.

use std::io;
use std::net::{TcpListener, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::Config;
use crate::conn::Conn;
use crate::dial::serve_conn_with_config;
use crate::errors::{Error, Result};

/// Wraps a [`TcpListener`] with shared tcpduplex defaults for accepted peers.
pub struct Server {
    cfg: Option<Config>,
    ln: TcpListener,
    closed: AtomicBool,
}

impl Server {
    /// Opens a TCP listener. `cfg` may be `None` (defaults applied per connection).
    pub fn listen(addr: impl ToSocketAddrs, cfg: Option<Config>) -> Result<Self> {
        let ln = TcpListener::bind(addr).map_err(|e| Error::wrap("listen", e))?;
        ln.set_nonblocking(false).ok();
        Ok(Self {
            cfg,
            ln,
            closed: AtomicBool::new(false),
        })
    }

    /// Listener address.
    pub fn addr(&self) -> io::Result<std::net::SocketAddr> {
        self.ln.local_addr()
    }

    /// Shuts down the listener.
    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        // Unblock Accept by connecting to self then dropping — platform portable:
        if let Ok(addr) = self.ln.local_addr() {
            let _ = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200));
        }
        Ok(())
    }

    /// Accepts connections until [`Server::close`] or accept failure.
    ///
    /// Each accepted socket is handed to `on_connect` after a successful handshake,
    /// on a dedicated thread.
    pub fn serve<F>(&self, on_connect: F) -> Result<()>
    where
        F: Fn(Arc<Conn>) + Send + Sync + 'static,
    {
        let on_connect = Arc::new(on_connect);
        let mut join_handles: Vec<thread::JoinHandle<()>> = Vec::new();

        loop {
            if self.closed.load(Ordering::SeqCst) {
                for h in join_handles {
                    let _ = h.join();
                }
                return Err(Error::Closed);
            }
            let (stream, _) = match self.ln.accept() {
                Ok(v) => v,
                Err(e) => {
                    for h in join_handles {
                        let _ = h.join();
                    }
                    if self.closed.load(Ordering::SeqCst) {
                        return Err(Error::Closed);
                    }
                    return Err(Error::wrap("accept", e));
                }
            };

            if self.closed.load(Ordering::SeqCst) {
                for h in join_handles {
                    let _ = h.join();
                }
                return Err(Error::Closed);
            }

            let cfg = self.cfg.clone();
            let cb = on_connect.clone();
            let handle = thread::spawn(move || {
                let conn = match serve_conn_with_config(stream, cfg.as_ref()) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                cb(conn);
            });
            join_handles.push(handle);
        }
    }
}
