//! `authorized_keys` lines: `sao-ed25519 <base64> [comment...]`.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::CoreError;

pub const KEY_TYPE_ED25519: &str = "sao-ed25519";

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub key_type: String,
    pub verifying_key: VerifyingKey,
    /// SHA-256(pubkey 32 bytes) hex — matches `AuthResponse.fingerprint`.
    pub fingerprint_hex: String,
    pub comment: String,
}

/// Fingerprint for Ed25519 raw public key (32 bytes): `hex(sha256(pk))`.
pub fn ed25519_fingerprint_hex(pk: &VerifyingKey) -> String {
    let b = pk.to_bytes();
    hex::encode(Sha256::digest(b))
}

pub fn load_authorized_keys(path: &Path) -> Result<Vec<AuthorizedKey>, CoreError> {
    let s = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (lineno, line) in s.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key_type = parts.next().unwrap().to_string();
        let b64 = parts.next().ok_or_else(|| {
            CoreError::AuthorizedKeys(format!("line {}: missing key blob", lineno + 1))
        })?;
        let comment: String = parts.collect::<Vec<_>>().join(" ");
        if key_type != KEY_TYPE_ED25519 {
            continue;
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| CoreError::AuthorizedKeys(format!("line {}: {e}", lineno + 1)))?;
        if raw.len() != 32 {
            return Err(CoreError::AuthorizedKeys(format!(
                "line {}: ed25519 key must decode to 32 bytes",
                lineno + 1
            )));
        }
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::AuthorizedKeys(format!("line {}: bad key len", lineno + 1)))?;
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| CoreError::AuthorizedKeys(format!("line {}: {e}", lineno + 1)))?;
        let fp = ed25519_fingerprint_hex(&vk);
        out.push(AuthorizedKey {
            key_type,
            verifying_key: vk,
            fingerprint_hex: fp,
            comment,
        });
    }
    if out.is_empty() {
        return Err(CoreError::AuthorizedKeys(
            "no sao-ed25519 keys in file".into(),
        ));
    }
    Ok(out)
}

pub fn find_key<'a>(keys: &'a [AuthorizedKey], fingerprint_hex: &str) -> Option<&'a AuthorizedKey> {
    let fp = fingerprint_hex.trim().to_lowercase();
    keys.iter().find(|k| k.fingerprint_hex == fp)
}

pub fn verify_ed25519_signature(
    vk: &VerifyingKey,
    message: &[u8],
    sig_b64: &str,
) -> Result<(), CoreError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| CoreError::Ed25519(e.to_string()))?;
    let sig: Signature = raw
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Ed25519("bad signature length".into()))?;
    vk.verify_strict(message, &sig)
        .map_err(|_| CoreError::Ed25519("signature verify failed".into()))
}
