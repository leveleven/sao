//! Canonical bytes signed in auth (`docs/protocol.md` §4.1).

const PREFIX: &[u8] = b"sao-auth-v1\0";

/// `UTF-8("sao-auth-v1\0") || nonce || UTF-8(session_id)`.
pub fn signing_bytes(nonce: &[u8], session_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(PREFIX.len() + nonce.len() + session_id.len());
    v.extend_from_slice(PREFIX);
    v.extend_from_slice(nonce);
    v.extend_from_slice(session_id.as_bytes());
    v
}
