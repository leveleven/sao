//! Protocol-level errors (framing); JSON/application errors use `Error` frame payloads.

use std::fmt;

/// Framing or version errors while reading/writing SAO frames.
#[derive(Debug)]
pub enum ProtocolError {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// Connection closed before a full header or payload.
    UnexpectedEof,
    /// First three bytes were not `SAO`.
    InvalidMagic,
    /// `version` field is not [`crate::VERSION`](crate::VERSION).
    UnsupportedVersion { got: u8 },
    /// Declared payload length exceeds configured maximum.
    PayloadTooLarge { len: u32, max: u32 },
    /// Declared payload length does not fit in `usize` on this platform.
    PayloadLengthOverflow { len: u32 },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "io error: {e}"),
            ProtocolError::UnexpectedEof => write!(f, "unexpected end of stream"),
            ProtocolError::InvalidMagic => write!(f, "invalid frame magic (expected SAO)"),
            ProtocolError::UnsupportedVersion { got } => {
                write!(f, "unsupported protocol version: 0x{got:02x}")
            }
            ProtocolError::PayloadTooLarge { len, max } => {
                write!(f, "payload length {len} exceeds maximum {max}")
            }
            ProtocolError::PayloadLengthOverflow { len } => {
                write!(f, "payload length {len} too large for this platform")
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::Io(e)
    }
}
