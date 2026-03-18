//! Client Ed25519 agent key load/store (`~/.sao/keys/agent.ed25519`).

use std::path::Path;

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::authorized_keys::{ed25519_fingerprint_hex, KEY_TYPE_ED25519};
use crate::CoreError;

const FILE_HEADER: &str = "sao-ed25519-private-v1";

/// Load or create a signing key at `path` (parent dirs created).
pub fn load_or_create_signing_key(path: &Path) -> Result<SigningKey, CoreError> {
    if path.exists() {
        let s = std::fs::read_to_string(path)?;
        let mut sk = None;
        for line in s.lines() {
            let line = line.trim();
            if line == FILE_HEADER || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let raw = base64::engine::general_purpose::STANDARD
                .decode(line)
                .map_err(|e| CoreError::Ed25519(e.to_string()))?;
            if raw.len() != 32 {
                return Err(CoreError::Ed25519("private key must be 32 bytes".into()));
            }
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Ed25519("private key must be 32 bytes".into()))?;
            let key = SigningKey::from_bytes(&arr);
            sk = Some(key);
            break;
        }
        return sk.ok_or_else(|| CoreError::Ed25519("no key material in file".into()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let key = SigningKey::generate(&mut OsRng);
    let b64 = base64::engine::general_purpose::STANDARD.encode(key.to_bytes());
    let body = format!("{FILE_HEADER}\n{b64}\n");
    std::fs::write(path, body)?;
    tracing::info!(
        fingerprint = %ed25519_fingerprint_hex(&key.verifying_key()),
        "generated new {}",
        KEY_TYPE_ED25519
    );
    Ok(key)
}

pub fn sign_auth_message(key: &SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sig = key.sign(message);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}
