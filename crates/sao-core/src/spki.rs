//! SPKI SHA-256 fingerprint for TLS certificate pinning (`docs/protocol.md` §2.1).

use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::CoreError;

/// SHA-256 hash of SubjectPublicKeyInfo DER as 32 bytes.
pub fn spki_sha256_bytes_from_cert_der(der: &[u8]) -> Result<[u8; 32], CoreError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| CoreError::X509(e.to_string()))?;
    let spki = cert.subject_pki.raw;
    Ok(Sha256::digest(spki).into())
}

/// Hex lowercase (64 chars).
pub fn spki_sha256_hex_from_cert_der(der: &[u8]) -> Result<String, CoreError> {
    Ok(hex::encode(spki_sha256_bytes_from_cert_der(der)?))
}

/// First PEM `CERTIFICATE` block → SPKI SHA-256 hex.
pub fn spki_sha256_hex_from_pem(pem: &str) -> Result<String, CoreError> {
    const START: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem
        .find(START)
        .ok_or_else(|| CoreError::X509("no BEGIN CERTIFICATE".into()))?;
    let rest = &pem[start + START.len()..];
    let end = rest
        .find(END)
        .ok_or_else(|| CoreError::X509("no END CERTIFICATE".into()))?;
    let b64: String = rest[..end]
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| CoreError::X509(e.to_string()))?;
    spki_sha256_hex_from_cert_der(&der)
}
