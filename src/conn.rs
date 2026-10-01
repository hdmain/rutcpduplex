//! Encrypted full-duplex connection after handshake.

use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, select, Receiver, Sender};

use crate::config::FrozenConfig;
use crate::crypto::Session;
use crate::errors::{Error, Result};
use crate::protocol::{self, MSG_CLOSE, MSG_PING, MSG_PONG, MSG_TEXT};

struct Outbound {
    typ: u8,
    pt: Vec<u8>,
}

enum RecvState {
    Open,
    Closed(Error),
}

/// Encrypted full-duplex tcpduplex session after handshake.
pub struct Conn {
    nc: Arc<Mutex<TcpStream>>,
    sess: Arc<Session>,
    cfg: FrozenConfig,

    send_tx: Mutex<Option<Sender<Outbound>>>,

    recv_tx: Mutex<Option<Sender<Vec<u8>>>>,
    recv_rx: Receiver<Vec<u8>>,
    recv_state: Mutex<RecvState>,

    msg_jobs_tx: Option<Sender<Vec<u8>>>,

    callback_dropped: AtomicU64,

    /// Shared stop flag; writer/deliver poll this via channel disconnect.
    stopped: Arc<AtomicBool>,
    stop_tx: Mutex<Option<Sender<()>>>,

    shutdown_started: AtomicBool,
    closed: AtomicBool,

    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl Conn {
    pub(crate) fn new(nc: TcpStream, sess: Session, cfg: FrozenConfig) -> Arc<Self> {
        let (send_tx, send_rx) = bounded::<Outbound>(cfg.send_queue_depth);
        let (recv_tx, recv_rx) = bounded::<Vec<u8>>(cfg.receive_queue_depth);
        let (stop_tx, stop_rx) = bounded::<()>(0);

        let (msg_jobs_tx, msg_jobs_rx) = if cfg.on_message.is_some() {
            let (t, r) = bounded(cfg.on_message_buffer_depth);
            (Some(t), Some(r))
        } else {
            (None, None)
        };

        let stopped = Arc::new(AtomicBool::new(false));

        let conn = Arc::new(Conn {
            nc: Arc::new(Mutex::new(nc)),
            sess: Arc::new(sess),
            cfg,
            send_tx: Mutex::new(Some(send_tx)),
            recv_tx: Mutex::new(Some(recv_tx)),
            recv_rx,
            recv_state: Mutex::new(RecvState::Open),
            msg_jobs_tx,
            callback_dropped: AtomicU64::new(0),
            stopped: stopped.clone(),
            stop_tx: Mutex::new(Some(stop_tx)),
            shutdown_started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            handles: Mutex::new(Vec::new()),
        });

        let mut handles = Vec::new();

        if let Some(rx) = msg_jobs_rx {
            let on_message = conn.cfg.on_message.clone().expect("on_message");
            let stop = stop_rx.clone();
            handles.push(
                thread::Builder::new()
                    .name("rutcpduplex-deliver".into())
                    .spawn(move || deliver_loop(rx, stop, on_message))
                    .expect("spawn deliver"),
            );
        }

        {
            let this = conn.clone();
            let stop = stop_rx.clone();
            handles.push(
                thread::Builder::new()
                    .name("rutcpduplex-write".into())
                    .spawn(move || this.write_loop(send_rx, stop))
                    .expect("spawn write"),
            );
        }

        {
            let this = conn.clone();
            let stop = stop_rx;
            handles.push(
                thread::Builder::new()
                    .name("rutcpduplex-read".into())
                    .spawn(move || this.read_loop(stop))
                    .expect("spawn read"),
            );
        }

        *conn.handles.lock().unwrap() = handles;
        conn
    }

    fn send_sender(&self) -> Result<Sender<Outbound>> {
        self.send_tx
            .lock()
            .unwrap()
            .clone()
            .ok_or(Error::Closed)
    }

    /// Queues an application message (encrypted as `MsgText`).
    pub fn send(&self, payload: &[u8]) -> Result<()> {
        self.send_deadline(payload, None)
    }

    /// Like [`send`](Self::send) but fails if `deadline` is reached first.
    pub fn send_deadline(&self, payload: &[u8], deadline: Option<Instant>) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        if payload.len() > self.cfg.max_message_bytes {
            return Err(Error::MessageTooLarge);
        }
        let out = Outbound {
            typ: MSG_TEXT,
            pt: payload.to_vec(),
        };
        self.enqueue(out, deadline)
    }

    fn enqueue(&self, out: Outbound, deadline: Option<Instant>) -> Result<()> {
        let tx = self.send_sender()?;
        loop {
            if self.closed.load(Ordering::SeqCst) || self.stopped.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            if let Some(dl) = deadline {
                let now = Instant::now();
                if now >= dl {
                    return Err(Error::Other("context canceled / deadline exceeded".into()));
                }
                let wait = dl.saturating_duration_since(now);
                match tx.send_timeout(out, wait) {
                    Ok(()) => return Ok(()),
                    Err(crossbeam_channel::SendTimeoutError::Timeout(o)) => {
                        // retry with same payload
                        return self.enqueue(o, deadline);
                    }
                    Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                        return Err(Error::Closed);
                    }
                }
            } else {
                return tx.send(out).map_err(|_| Error::Closed);
            }
        }
    }

    /// Blocks until the next application message or an error.
    pub fn receive(&self) -> Result<Vec<u8>> {
        self.receive_deadline(None)
    }

    /// Like [`receive`](Self::receive) with an optional deadline.
    pub fn receive_deadline(&self, deadline: Option<Instant>) -> Result<Vec<u8>> {
        if self.cfg.on_message.is_some() {
            return Err(Error::ReceiveDisabled);
        }
        if let Some(dl) = deadline {
            let now = Instant::now();
            if now >= dl {
                return Err(Error::Other("context canceled / deadline exceeded".into()));
            }
            let wait = dl.saturating_duration_since(now);
            match self.recv_rx.recv_timeout(wait) {
                Ok(m) => Ok(m),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    Err(Error::Other("context canceled / deadline exceeded".into()))
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => self.recv_error(),
            }
        } else {
            match self.recv_rx.recv() {
                Ok(m) => Ok(m),
                Err(_) => self.recv_error(),
            }
        }
    }

    fn recv_error(&self) -> Result<Vec<u8>> {
        let st = self.recv_state.lock().unwrap();
        match &*st {
            RecvState::Closed(err) => Err(clone_error(err)),
            RecvState::Open => Err(Error::Closed),
        }
    }

    /// Counts inbound messages dropped because the `on_message` buffer was full.
    pub fn callback_dropped(&self) -> u64 {
        self.callback_dropped.load(Ordering::SeqCst)
    }

    /// Graceful shutdown with unlimited waits.
    pub fn close(&self) -> Result<()> {
        self.shutdown(None)
    }

    /// Tears down the session; `timeout` bounds waits for writer/reader completion.
    pub fn shutdown(&self, timeout: Option<Duration>) -> Result<()> {
        if self
            .shutdown_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::Closed);
        }
        self.closed.store(true, Ordering::SeqCst);
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.stop_tx.lock().unwrap().take();

        let handles = std::mem::take(&mut *self.handles.lock().unwrap());

        // Give the writer a brief moment to flush MsgClose, then always tear down
        // the TCP socket so the reader cannot block forever.
        let mut writer = None;
        let mut others = Vec::new();
        for h in handles {
            if h.thread().name() == Some("rutcpduplex-write") {
                writer = Some(h);
            } else {
                others.push(h);
            }
        }

        if let Some(h) = writer {
            let t = Some(timeout.unwrap_or(Duration::from_millis(500)));
            let _ = join_with_timeout(h, t);
        }

        {
            let g = self.nc.lock().unwrap();
            let _ = g.shutdown(std::net::Shutdown::Both);
        }

        for h in others {
            let t = Some(timeout.unwrap_or(Duration::from_secs(2)));
            let _ = join_with_timeout(h, t);
        }
        Ok(())
    }

    /// Clone of the underlying TCP stream.
    pub fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.nc.lock().unwrap().try_clone()
    }

    /// Remote address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.nc.lock().unwrap().peer_addr()
    }

    /// Local address.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.nc.lock().unwrap().local_addr()
    }

    /// Plaintext size limit for this session.
    pub fn max_message_bytes(&self) -> usize {
        self.cfg.max_message_bytes
    }

    fn finish_recv(&self, err: Error) {
        {
            let mut st = self.recv_state.lock().unwrap();
            if matches!(*st, RecvState::Closed(_)) {
                return;
            }
            *st = RecvState::Closed(err);
        }
        let _ = self.recv_tx.lock().unwrap().take();
    }

    fn read_loop(self: &Arc<Self>, _stop: Receiver<()>) {
        let mut stream = match self.nc.lock().unwrap().try_clone() {
            Ok(s) => s,
            Err(e) => {
                self.finish_recv(Error::Io(e));
                return;
            }
        };

        loop {
            if self.stopped.load(Ordering::SeqCst) {
                // Still try to read until TCP ends; shutdown will force EOF.
            }
            let (msg_type, sealed) = match protocol::read_record(&mut stream) {
                Ok(v) => v,
                Err(e) => {
                    self.finish_recv(map_read_err(e));
                    return;
                }
            };
            let pt = match self.sess.open(&sealed) {
                Ok(p) => p,
                Err(e) => {
                    self.finish_recv(Error::Protocol(e));
                    return;
                }
            };
            match msg_type {
                MSG_TEXT => {
                    if pt.len() > self.cfg.max_message_bytes {
                        self.finish_recv(Error::MessageTooLarge);
                        return;
                    }
                    if let Some(ref mtx) = self.msg_jobs_tx {
                        match mtx.try_send(pt) {
                            Ok(()) => {}
                            Err(crossbeam_channel::TrySendError::Full(_)) => {
                                if self.cfg.disconnect_on_slow_callback_consumer {
                                    self.finish_recv(Error::SlowConsumer);
                                    return;
                                }
                                self.callback_dropped.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                                self.finish_recv(Error::Closed);
                                return;
                            }
                        }
                    } else {
                        let tx = self.recv_tx.lock().unwrap().clone();
                        let Some(tx) = tx else {
                            return;
                        };
                        if self.stopped.load(Ordering::SeqCst) {
                            self.finish_recv(Error::Closed);
                            return;
                        }
                        if tx.send(pt).is_err() {
                            self.finish_recv(Error::Closed);
                            return;
                        }
                    }
                }
                MSG_PING => {
                    if self.stopped.load(Ordering::SeqCst) {
                        self.finish_recv(Error::Closed);
                        return;
                    }
                    if let Ok(stx) = self.send_sender() {
                        let _ = stx.send(Outbound {
                            typ: MSG_PONG,
                            pt,
                        });
                    }
                }
                MSG_PONG => {}
                MSG_CLOSE => {
                    self.finish_recv(Error::Eof);
                    return;
                }
                _ => {
                    self.finish_recv(Error::Protocol(protocol::ProtocolError::BadFrame));
                    return;
                }
            }
        }
    }

    fn write_loop(self: &Arc<Self>, send_rx: Receiver<Outbound>, stop: Receiver<()>) {
        let mut stream = match self.nc.lock().unwrap().try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        // Prevent indefinite block during shutdown flush / MsgClose.
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        let write_out = |stream: &mut TcpStream, out: &Outbound| -> bool {
            let sealed = match self.sess.seal(&out.pt) {
                Ok(s) => s,
                Err(_) => return false,
            };
            if protocol::write_record(stream, out.typ, &sealed).is_err() {
                return false;
            }
            let _ = stream.flush();
            true
        };

        loop {
            if self.stopped.load(Ordering::SeqCst) {
                break;
            }
            select! {
                recv(stop) -> _ => break,
                recv(send_rx) -> msg => {
                    match msg {
                        Ok(out) => {
                            if !write_out(&mut stream, &out) {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                default(Duration::from_millis(20)) => {}
            }
        }

        while let Ok(out) = send_rx.try_recv() {
            if !write_out(&mut stream, &out) {
                return;
            }
        }
        let close_msg = Outbound {
            typ: MSG_CLOSE,
            pt: Vec::new(),
        };
        let _ = write_out(&mut stream, &close_msg);
    }
}

fn join_with_timeout(h: JoinHandle<()>, timeout: Option<Duration>) -> Result<()> {
    match timeout {
        None => {
            let _ = h.join();
            Ok(())
        }
        Some(d) => {
            // Poll join via helper thread.
            let (tx, rx) = bounded::<()>(1);
            thread::spawn(move || {
                let _ = h.join();
                let _ = tx.send(());
            });
            match rx.recv_timeout(d) {
                Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => Ok(()),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    Err(Error::Other("shutdown timed out".into()))
                }
            }
        }
    }
}

fn deliver_loop(
    rx: Receiver<Vec<u8>>,
    stop: Receiver<()>,
    on_message: crate::config::OnMessageFn,
) {
    loop {
        select! {
            recv(rx) -> msg => {
                match msg {
                    Ok(payload) => on_message(payload),
                    Err(_) => return,
                }
            }
            recv(stop) -> _ => {
                while let Ok(payload) = rx.try_recv() {
                    on_message(payload);
                }
                return;
            }
        }
    }
}

fn map_read_err(e: protocol::ProtocolError) -> Error {
    match &e {
        protocol::ProtocolError::Io(s) => {
            let lower = s.to_ascii_lowercase();
            if lower.contains("unexpected eof")
                || lower.contains("early eof")
                || lower.contains("connection reset")
                || lower.contains("broken pipe")
                || lower.contains("forcibly closed")
                || lower.contains("wsarecv")
                || lower.contains("10053")
                || lower.contains("10054")
            {
                Error::Eof
            } else {
                Error::Protocol(e)
            }
        }
        _ => Error::Protocol(e),
    }
}

fn clone_error(err: &Error) -> Error {
    match err {
        Error::Closed => Error::Closed,
        Error::ReceiveDisabled => Error::ReceiveDisabled,
        Error::MessageTooLarge => Error::MessageTooLarge,
        Error::InboundDropped => Error::InboundDropped,
        Error::SlowConsumer => Error::SlowConsumer,
        Error::UnsupportedProtocol => Error::UnsupportedProtocol,
        Error::HandshakeAuthentication => Error::HandshakeAuthentication,
        Error::PeerFingerprintMismatch => Error::PeerFingerprintMismatch,
        Error::Eof => Error::Eof,
        Error::Protocol(p) => Error::Protocol(p.clone()),
        Error::Io(e) => Error::Io(io::Error::new(e.kind(), e.to_string())),
        Error::Other(s) => Error::Other(s.clone()),
        Error::Op { op, source } => Error::Other(format!("{op}: {source}")),
    }
}
