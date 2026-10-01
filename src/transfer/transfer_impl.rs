//! Send / receive transfer logic.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::conn::Conn;
use crate::errors::Error as ConnError;

use super::errors::TransferError;
use super::frame::*;
use super::id::TransferId;
use super::options::{effective_chunk_size, normalize_options, Options};

/// Trait for reading at absolute offsets (Go `io.ReaderAt`).
pub trait ReaderAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize>;
}

/// Trait for writing at absolute offsets (Go `io.WriterAt`).
pub trait WriterAt {
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize>;
}

impl ReaderAt for File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let mut f = self.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read(buf)
    }
}

impl WriterAt for File {
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        let mut f = self.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(buf)?;
        Ok(buf.len())
    }
}

impl ReaderAt for [u8] {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= self.len() {
            return Ok(0);
        }
        let n = std::cmp::min(buf.len(), self.len() - off);
        buf[..n].copy_from_slice(&self[off..off + n]);
        Ok(n)
    }
}

/// In-memory buffer implementing ReaderAt / WriterAt for tests and callers.
#[derive(Default)]
pub struct MemFile {
    pub data: std::sync::Mutex<Vec<u8>>,
}

impl MemFile {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }
}

impl ReaderAt for MemFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let data = self.data.lock().unwrap();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = std::cmp::min(buf.len(), data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
}

impl WriterAt for MemFile {
    fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        let mut data = self.data.lock().unwrap();
        let off = offset as usize;
        let end = off + buf.len();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        Ok(buf.len())
    }
}

struct SliceReader<'a>(&'a [u8]);
impl ReaderAt for SliceReader<'_> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.0.read_at(buf, offset)
    }
}

/// Transfers `meta.size` bytes from `r` to the peer over `conn`.
pub fn send(
    conn: Arc<Conn>,
    r: &dyn ReaderAt,
    mut meta: Meta,
    opts: Option<&Options>,
) -> Result<(), TransferError> {
    let opts = normalize_options(opts);
    if meta.size < 0 {
        return Err(TransferError::SizeMismatch);
    }
    if meta.id == TransferId::default() {
        meta.id = TransferId::new()?;
    }
    if is_zero_hash(&meta.hash) {
        meta.hash = hash_reader_at(r, meta.size)?;
    }

    let mut attempts = 0usize;
    let mut last_err: Option<TransferError> = None;
    let mut conn = conn;
    loop {
        attempts += 1;
        if attempts > opts.max_attempts {
            return match last_err {
                Some(e) => Err(TransferError::TooManyRetriesCause(e.to_string())),
                None => Err(TransferError::TooManyRetries),
            };
        }
        match send_once(&conn, r, &meta, &opts) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err.clone());
                if opts.redial.is_none() || !is_retriable(&err) {
                    return Err(err);
                }
                let redial = opts.redial.as_ref().unwrap();
                conn = redial().map_err(TransferError::Redial)?;
            }
        }
    }
}

/// Opens `path` and sends its contents.
pub fn send_file(
    conn: Arc<Conn>,
    path: impl AsRef<Path>,
    opts: Option<&Options>,
) -> Result<(), TransferError> {
    let path = path.as_ref();
    let f = File::open(path)?;
    let meta = Meta {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        size: f.metadata()?.len() as i64,
        ..Meta::default()
    };
    send(conn, &f, meta, opts)
}

fn send_once(
    conn: &Conn,
    r: &dyn ReaderAt,
    meta: &Meta,
    opts: &Options,
) -> Result<(), TransferError> {
    let chunk_size = effective_chunk_size(conn, opts.chunk_size);
    let offer = encode_offer(meta)?;
    conn.send(&offer).map_err(map_conn_err)?;

    let msg = conn.receive().map_err(map_conn_err)?;
    let dec = decode_frame(&msg)?;
    match dec.typ {
        TYPE_REJECT => {
            if dec.id != meta.id {
                return Err(TransferError::BadFrame);
            }
            if !dec.reason.is_empty() {
                return Err(TransferError::RejectedReason(dec.reason));
            }
            return Err(TransferError::Rejected);
        }
        TYPE_ACCEPT => {
            if dec.id != meta.id {
                return Err(TransferError::BadFrame);
            }
        }
        _ => return Err(TransferError::BadFrame),
    }

    let offset = dec.offset;
    if offset < 0 || offset > meta.size {
        return Err(TransferError::ResumePastEnd);
    }
    if let Some(ref cb) = opts.on_progress {
        cb(offset, meta.size);
    }
    if offset == meta.size {
        return finish_send(conn, meta);
    }

    let mut acked = offset;
    let mut next_off = offset;
    let mut buf = vec![0u8; chunk_size];

    while acked < meta.size {
        while count_in_flight(acked, next_off, chunk_size) < opts.window && next_off < meta.size {
            let mut n = chunk_size as i64;
            if next_off + n > meta.size {
                n = meta.size - next_off;
            }
            read_full_at(r, &mut buf[..n as usize], next_off)?;
            let frame = encode_chunk(meta.id, next_off, &buf[..n as usize]);
            conn.send(&frame).map_err(map_conn_err)?;
            next_off += n;
        }

        let msg = conn.receive().map_err(map_conn_err)?;
        let dec = decode_frame(&msg)?;
        match dec.typ {
            TYPE_ACK => {
                if dec.id != meta.id {
                    return Err(TransferError::BadFrame);
                }
                if dec.offset < acked || dec.offset > next_off {
                    return Err(TransferError::BadFrame);
                }
                acked = dec.offset;
                if let Some(ref cb) = opts.on_progress {
                    cb(acked, meta.size);
                }
            }
            TYPE_ABORT => {
                if dec.id != meta.id {
                    return Err(TransferError::BadFrame);
                }
                if !dec.reason.is_empty() {
                    return Err(TransferError::AbortedReason(dec.reason));
                }
                return Err(TransferError::Aborted);
            }
            _ => return Err(TransferError::BadFrame),
        }
    }

    finish_send(conn, meta)
}

fn count_in_flight(acked: i64, next_off: i64, chunk_size: usize) -> usize {
    if next_off <= acked {
        return 0;
    }
    let remain = next_off - acked;
    let cs = chunk_size as i64;
    ((remain + cs - 1) / cs) as usize
}

fn finish_send(conn: &Conn, meta: &Meta) -> Result<(), TransferError> {
    conn.send(&encode_done(meta.id, true, meta.hash))
        .map_err(map_conn_err)?;
    let msg = conn.receive().map_err(map_conn_err)?;
    let dec = decode_frame(&msg)?;
    if dec.typ != TYPE_DONE || dec.id != meta.id {
        return Err(TransferError::BadFrame);
    }
    if !dec.ok {
        return Err(TransferError::HashMismatch);
    }
    Ok(())
}

/// Accepts one transfer and writes bytes into `w` at absolute offsets.
pub fn receive(
    conn: Arc<Conn>,
    w: &dyn WriterAt,
    resume_offset: i64,
    opts: Option<&Options>,
) -> Result<Meta, TransferError> {
    receive_inner(conn, w, None, resume_offset, opts)
}

/// Accepts one transfer with an explicit [`ReaderAt`] used for resume hashing.
pub fn receive_with_reader(
    conn: Arc<Conn>,
    w: &dyn WriterAt,
    r: &dyn ReaderAt,
    resume_offset: i64,
    opts: Option<&Options>,
) -> Result<Meta, TransferError> {
    receive_inner(conn, w, Some(r), resume_offset, opts)
}

fn receive_inner(
    mut conn: Arc<Conn>,
    w: &dyn WriterAt,
    r: Option<&dyn ReaderAt>,
    resume_offset: i64,
    opts: Option<&Options>,
) -> Result<Meta, TransferError> {
    let opts = normalize_options(opts);
    if resume_offset < 0 {
        return Err(TransferError::ResumePastEnd);
    }

    let mut meta = Meta::default();
    let mut have_meta = false;
    let mut written = resume_offset;
    let mut attempts = 0usize;
    let mut last_err: Option<TransferError> = None;

    loop {
        attempts += 1;
        if attempts > opts.max_attempts {
            return match last_err {
                Some(e) => Err(TransferError::TooManyRetriesCause(e.to_string())),
                None => Err(TransferError::TooManyRetries),
            };
        }
        match receive_once(&conn, w, r, written, have_meta, &meta, &opts) {
            Ok((m, _)) => return Ok(m),
            Err((m, n, err)) => {
                last_err = Some(err.clone());
                if m.id != TransferId::default() {
                    meta = m;
                    have_meta = true;
                }
                if n > written {
                    written = n;
                }
                if opts.redial.is_none() || !is_retriable(&err) {
                    return Err(err);
                }
                let redial = opts.redial.as_ref().unwrap();
                conn = redial().map_err(TransferError::Redial)?;
            }
        }
    }
}

type RecvOnceErr = (Meta, i64, TransferError);

fn receive_once(
    conn: &Conn,
    w: &dyn WriterAt,
    r: Option<&dyn ReaderAt>,
    resume_offset: i64,
    expect_meta: bool,
    want: &Meta,
    opts: &Options,
) -> Result<(Meta, i64), RecvOnceErr> {
    let msg = conn.receive().map_err(|e| (want.clone(), resume_offset, map_conn_err(e)))?;
    let dec = decode_frame(&msg).map_err(|e| (want.clone(), resume_offset, e))?;
    if dec.typ != TYPE_OFFER {
        return Err((want.clone(), resume_offset, TransferError::BadFrame));
    }
    let meta = dec.meta;
    if expect_meta && meta.id != want.id {
        let _ = conn.send(&encode_reject(meta.id, "unexpected transfer id"));
        return Err((want.clone(), resume_offset, TransferError::BadFrame));
    }
    if resume_offset > meta.size {
        let _ = conn.send(&encode_reject(meta.id, "resume past end"));
        return Err((meta, resume_offset, TransferError::ResumePastEnd));
    }
    if let Some(ref accept) = opts.accept {
        if let Err(reason) = accept(&meta) {
            let _ = conn.send(&encode_reject(meta.id, &reason));
            return Err((
                meta,
                resume_offset,
                TransferError::RejectedReason(reason),
            ));
        }
    }
    conn.send(&encode_accept(meta.id, resume_offset))
        .map_err(|e| (meta.clone(), resume_offset, map_conn_err(e)))?;

    if let Some(ref cb) = opts.on_progress {
        cb(resume_offset, meta.size);
    }
    if resume_offset == meta.size {
        return finalize_receive(conn, w, r, &meta, resume_offset)
            .map_err(|e| (meta.clone(), resume_offset, e))
            .map(|m| (m, resume_offset));
    }

    let mut hw = new_hashing_writer(w, r, resume_offset)
        .map_err(|e| {
            let _ = conn.send(&encode_abort(meta.id, &e.to_string()));
            (meta.clone(), resume_offset, e)
        })?;

    let mut written = resume_offset;
    let mut chunks_since_ack = 0usize;

    while written < meta.size {
        let msg = conn
            .receive()
            .map_err(|e| (meta.clone(), written, map_conn_err(e)))?;
        let dec = decode_frame(&msg).map_err(|e| (meta.clone(), written, e))?;
        match dec.typ {
            TYPE_CHUNK => {
                if dec.id != meta.id {
                    return Err((meta, written, TransferError::BadFrame));
                }
                if dec.offset != written {
                    return Err((meta, written, TransferError::BadFrame));
                }
                if dec.offset + dec.data.len() as i64 > meta.size {
                    return Err((meta, written, TransferError::BadFrame));
                }
                if let Err(e) = hw.write_at(&dec.data, dec.offset as u64) {
                    let _ = conn.send(&encode_abort(meta.id, &e.to_string()));
                    return Err((meta, written, TransferError::Io(e)));
                }
                written = dec.offset + dec.data.len() as i64;
                chunks_since_ack += 1;
                if let Some(ref cb) = opts.on_progress {
                    cb(written, meta.size);
                }
                if chunks_since_ack >= opts.ack_every || written == meta.size {
                    conn.send(&encode_ack(meta.id, written))
                        .map_err(|e| (meta.clone(), written, map_conn_err(e)))?;
                    chunks_since_ack = 0;
                }
            }
            TYPE_DONE => {
                if dec.id != meta.id {
                    return Err((meta, written, TransferError::BadFrame));
                }
                if written != meta.size {
                    return Err((meta, written, TransferError::SizeMismatch));
                }
                let sum = hw.sum();
                return verify_and_ack_done(conn, &meta, written, &dec, sum)
                    .map_err(|e| (meta.clone(), written, e))
                    .map(|m| (m, written));
            }
            TYPE_ABORT => {
                if dec.id != meta.id {
                    return Err((meta, written, TransferError::BadFrame));
                }
                if !dec.reason.is_empty() {
                    return Err((meta, written, TransferError::AbortedReason(dec.reason)));
                }
                return Err((meta, written, TransferError::Aborted));
            }
            _ => return Err((meta, written, TransferError::BadFrame)),
        }
    }

    let msg = conn
        .receive()
        .map_err(|e| (meta.clone(), written, map_conn_err(e)))?;
    let dec = decode_frame(&msg).map_err(|e| (meta.clone(), written, e))?;
    if dec.typ != TYPE_DONE || dec.id != meta.id {
        return Err((meta, written, TransferError::BadFrame));
    }
    let sum = hw.sum();
    verify_and_ack_done(conn, &meta, written, &dec, sum)
        .map_err(|e| (meta.clone(), written, e))
        .map(|m| (m, written))
}

fn finalize_receive(
    conn: &Conn,
    w: &dyn WriterAt,
    r: Option<&dyn ReaderAt>,
    meta: &Meta,
    written: i64,
) -> Result<Meta, TransferError> {
    let sum = match new_hashing_writer(w, r, written) {
        Ok(hw) => hw.sum(),
        Err(_) => {
            if let Some(ra) = r {
                hash_reader_at(ra, meta.size)?
            } else {
                return Err(TransferError::Other(
                    "WriterAt does not implement ReaderAt; cannot verify hash".into(),
                ));
            }
        }
    };
    let msg = conn.receive().map_err(map_conn_err)?;
    let dec = decode_frame(&msg)?;
    if dec.typ != TYPE_DONE || dec.id != meta.id {
        return Err(TransferError::BadFrame);
    }
    verify_and_ack_done(conn, meta, written, &dec, sum)
}

fn verify_and_ack_done(
    conn: &Conn,
    meta: &Meta,
    _written: i64,
    dec: &Decoded,
    local: [u8; 32],
) -> Result<Meta, TransferError> {
    let mut ok = true;
    let mut expect = meta.hash;
    if is_zero_hash(&expect) {
        expect = dec.hash;
    }
    if !is_zero_hash(&expect) && local != expect {
        ok = false;
    }
    if !is_zero_hash(&dec.hash) && dec.hash != local {
        ok = false;
    }
    conn.send(&encode_done(meta.id, ok, local))
        .map_err(map_conn_err)?;
    if !ok {
        return Err(TransferError::HashMismatch);
    }
    Ok(meta.clone())
}

/// Receives one transfer into `dest_path`, resuming if a partial file exists.
pub fn receive_file(
    conn: Arc<Conn>,
    dest_path: impl AsRef<Path>,
    opts: Option<&Options>,
) -> Result<Meta, TransferError> {
    let dest_path = dest_path.as_ref();
    let resume = match std::fs::metadata(dest_path) {
        Ok(st) => st.len() as i64,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(TransferError::Io(e)),
    };

    let f = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dest_path)?;

    let meta = receive_inner(conn, &f, Some(&f), resume, opts)?;

    f.set_len(meta.size as u64)?;
    f.sync_all()?;
    Ok(meta)
}

struct HashingWriter<'a> {
    w: &'a dyn WriterAt,
    h: Sha256,
    offset: i64,
}

fn new_hashing_writer<'a>(
    w: &'a dyn WriterAt,
    r: Option<&dyn ReaderAt>,
    resume_offset: i64,
) -> Result<HashingWriter<'a>, TransferError> {
    let mut h = Sha256::new();
    if resume_offset > 0 {
        let ra = r.ok_or_else(|| {
            TransferError::Other(
                "WriterAt must implement ReaderAt to resume or verify".into(),
            )
        })?;
        copy_hash(&mut h, ra, resume_offset)?;
    }
    Ok(HashingWriter {
        w,
        h,
        offset: resume_offset,
    })
}

impl HashingWriter<'_> {
    fn write_at(&mut self, p: &[u8], off: u64) -> std::io::Result<usize> {
        if off as i64 != self.offset {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bad offset",
            ));
        }
        let n = self.w.write_at(p, off)?;
        if n > 0 {
            self.h.update(&p[..n]);
            self.offset += n as i64;
        }
        Ok(n)
    }

    fn sum(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let h = self.h.clone();
        let sum = h.finalize();
        out.copy_from_slice(&sum);
        out
    }
}

fn read_full_at(r: &dyn ReaderAt, buf: &mut [u8], off: i64) -> Result<(), TransferError> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read_at(&mut buf[got..], (off as u64) + got as u64)?;
        if n == 0 {
            return Err(TransferError::Other("unexpected EOF".into()));
        }
        got += n;
    }
    Ok(())
}

fn hash_reader_at(r: &dyn ReaderAt, size: i64) -> Result<[u8; 32], TransferError> {
    let mut h = Sha256::new();
    copy_hash(&mut h, r, size)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

fn copy_hash(h: &mut Sha256, r: &dyn ReaderAt, size: i64) -> Result<(), TransferError> {
    const BUF: usize = 256 << 10;
    let mut buf = vec![0u8; BUF];
    let mut off = 0i64;
    while off < size {
        let mut n = BUF;
        if n as i64 > size - off {
            n = (size - off) as usize;
        }
        read_full_at(r, &mut buf[..n], off)?;
        h.update(&buf[..n]);
        off += n as i64;
    }
    Ok(())
}

fn is_zero_hash(h: &[u8; 32]) -> bool {
    h.iter().all(|&b| b == 0)
}

fn map_conn_err(err: ConnError) -> TransferError {
    match err {
        ConnError::Closed | ConnError::Eof => TransferError::Closed,
        other => TransferError::Other(other.to_string()),
    }
}

fn is_retriable(err: &TransferError) -> bool {
    !matches!(
        err,
        TransferError::Rejected
            | TransferError::RejectedReason(_)
            | TransferError::HashMismatch
            | TransferError::SizeMismatch
            | TransferError::ResumePastEnd
            | TransferError::BadFrame
    )
}

/// Convenience: send raw bytes.
pub fn send_bytes(
    conn: Arc<Conn>,
    data: &[u8],
    name: &str,
    opts: Option<&Options>,
) -> Result<(), TransferError> {
    let meta = Meta {
        name: name.into(),
        size: data.len() as i64,
        ..Meta::default()
    };
    send(conn, &SliceReader(data), meta, opts)
}

/// Convenience receive into a [`MemFile`].
pub fn receive_mem(
    conn: Arc<Conn>,
    dst: &MemFile,
    resume_offset: i64,
    opts: Option<&Options>,
) -> Result<Meta, TransferError> {
    receive_inner(conn, dst, Some(dst), resume_offset, opts)
}
