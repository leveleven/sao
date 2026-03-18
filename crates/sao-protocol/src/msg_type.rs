//! `msg_type` byte values (`docs/protocol.md` §4).

/// Server → client: authentication challenge.
pub const AUTH_CHALLENGE: u8 = 0x01;
/// Client → server: signed response.
pub const AUTH_RESPONSE: u8 = 0x02;
/// Server → client: authentication outcome.
pub const AUTH_RESULT: u8 = 0x03;

/// Client → server: run shell command.
pub const EXEC_SHELL: u8 = 0x10;
/// Server → client: stdout chunk.
pub const STREAM_STDOUT: u8 = 0x11;
/// Server → client: stderr chunk.
pub const STREAM_STDERR: u8 = 0x12;
/// Server → client: process exit.
pub const EXEC_EXIT: u8 = 0x13;

/// Server → client: policy rejected the request.
pub const POLICY_DENIED: u8 = 0x20;

/// Bidirectional: protocol or application error.
pub const ERROR: u8 = 0xFF;
