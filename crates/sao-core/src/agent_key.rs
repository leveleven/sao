//! Client Ed25519 agent key load/store (`~/.sao/keys/agent.ed25519`).

use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::authorized_keys::{ed25519_fingerprint_hex, KEY_TYPE_ED25519};
use crate::CoreError;

const FILE_HEADER: &str = "sao-ed25519-private-v1";

/// Path for the public line next to the private key file (e.g. `agent.ed25519` → `agent.ed25519.pub`).
pub fn public_key_path(private_key_path: &Path) -> PathBuf {
    let mut p = private_key_path.to_path_buf();
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent.ed25519".to_string());
    p.pop();
    p.push(format!("{name}.pub"));
    p
}

/// Write `sao-ed25519 …` public line (for server `authorized_keys`) beside the private key file.
pub fn write_agent_public_key_file(
    private_key_path: &Path,
    key: &SigningKey,
) -> Result<(), CoreError> {
    let pub_path = public_key_path(private_key_path);
    if let Some(dir) = pub_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let line = format!(
        "{} {} agent",
        KEY_TYPE_ED25519,
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
    );
    let body = format!("# Append this line to the server's authorized_keys file.\n{line}\n");
    std::fs::write(&pub_path, body)?;
    Ok(())
}

/// Load or create a signing key at `path` (parent dirs created). Always refreshes the `.pub` file.
pub fn load_or_create_signing_key(path: &Path) -> Result<SigningKey, CoreError> {
    let key = if path.exists() {
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
        sk.ok_or_else(|| CoreError::Ed25519("no key material in file".into()))?
    } else {
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
        key
    };
    write_agent_public_key_file(path, &key)?;
    Ok(key)
}

pub fn sign_auth_message(key: &SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let sig = key.sign(message);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn public_key_path_suffix() {
        let p = Path::new("keys").join("agent.ed25519");
        assert_eq!(
            public_key_path(&p),
            Path::new("keys").join("agent.ed25519.pub")
        );
    }

    #[test]
    fn load_or_create_writes_pub() {
        let dir = tempdir().unwrap();
        let priv_path = dir.path().join("agent.ed25519");
        let pub_path = public_key_path(&priv_path);
        let sk = load_or_create_signing_key(&priv_path).unwrap();
        assert!(priv_path.exists());
        assert!(pub_path.exists());
        let pub_s = std::fs::read_to_string(&pub_path).unwrap();
        assert!(pub_s.contains(KEY_TYPE_ED25519));
        assert!(pub_s.contains(
            &base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().as_bytes())
        ));
        let sk2 = load_or_create_signing_key(&priv_path).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }
}
