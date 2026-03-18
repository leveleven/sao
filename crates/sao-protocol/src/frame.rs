//! Fixed 9-byte header + payload (`docs/protocol.md` §3).

use crate::{ProtocolError, MAGIC, VERSION};

/// Header size: magic(3) + version(1) + msg_type(1) + payload_len(4).
pub const HEADER_LEN: usize = 9;

/// Default maximum payload size in bytes (1 MiB, per spec recommendation).
pub const DEFAULT_MAX_PAYLOAD_LEN: u32 = 1024 * 1024;

/// One decoded frame: message type and raw JSON (or other) body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

/// Write the 9-byte header into `out` (must be `HEADER_LEN` bytes).
pub fn write_header(out: &mut [u8], version: u8, msg_type: u8, payload_len: u32) {
    debug_assert_eq!(out.len(), HEADER_LEN);
    out[0..3].copy_from_slice(&MAGIC);
    out[3] = version;
    out[4] = msg_type;
    out[5..9].copy_from_slice(&payload_len.to_be_bytes());
}

/// Parse header; returns `(version, msg_type, payload_len)`.
pub fn parse_header(hdr: &[u8; HEADER_LEN]) -> Result<(u8, u8, u32), ProtocolError> {
    if hdr[0..3] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = hdr[3];
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion { got: version });
    }
    let msg_type = hdr[4];
    let payload_len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
    Ok((version, msg_type, payload_len))
}
