//! Encrypted resumable file transfer over a tcpduplex session.
//!
//! Wire-compatible with Go package `github.com/hdmain/tcpduplex/transfer`.

mod errors;
mod frame;
mod id;
mod options;
mod transfer_impl;

pub use errors::TransferError;
pub use frame::Meta;
pub use id::{parse_id, TransferId};
pub use options::{DefaultOptions, Options};
pub use transfer_impl::{
    receive, receive_file, receive_mem, receive_with_reader, send, send_bytes, send_file, MemFile,
    ReaderAt, WriterAt,
};
