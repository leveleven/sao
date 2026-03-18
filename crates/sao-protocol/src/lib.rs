//! SAO wire protocol: magic, versioned frames, JSON payloads (`docs/protocol.md`).
//!
//! Use [`FrameCodec`] on any [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] stream
//! (e.g. TLS after handshake, plain TCP in tests).

mod codec;
mod error;
mod frame;
pub mod msg_type;

pub use codec::FrameCodec;
pub use error::ProtocolError;
pub use frame::{parse_header, write_header, Frame, DEFAULT_MAX_PAYLOAD_LEN, HEADER_LEN};

/// Frame magic bytes `S` `A` `O`.
pub const MAGIC: [u8; 3] = *b"SAO";
/// Current wire protocol version (§3).
pub const VERSION: u8 = 0x01;
