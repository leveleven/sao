use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid known_hosts line: {0}")]
    KnownHostsLine(String),
    #[error("unknown host:port in known_hosts: {0}")]
    KnownHostsMissing(String),
    #[error("invalid fingerprint (expect 64 hex chars): {0}")]
    InvalidFingerprint(String),
    #[error("authorized_keys: {0}")]
    AuthorizedKeys(String),
    #[error("no matching authorized key for fingerprint")]
    KeyNotFound,
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    #[error("ed25519: {0}")]
    Ed25519(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("x509 parse: {0}")]
    X509(String),
    #[error("missing config file: {0}")]
    MissingConfig(PathBuf),
}
