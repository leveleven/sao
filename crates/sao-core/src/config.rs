//! Server YAML config shape (`docs/protocol.md` — values are deployment-specific).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// TLS file paths and optional auto-generated self-signed cert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_cert_path")]
    pub cert_path: PathBuf,
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,
    /// If true and cert/key missing, generate self-signed PEM at the paths above.
    #[serde(default)]
    pub auto_generate_self_signed: bool,
}

fn default_cert_path() -> PathBuf {
    PathBuf::from("/etc/sao/tls/cert.pem")
}

fn default_key_path() -> PathBuf {
    PathBuf::from("/etc/sao/tls/key.pem")
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: default_cert_path(),
            key_path: default_key_path(),
            auto_generate_self_signed: false,
        }
    }
}

/// Shell / exec policy (deny substrings; extend via config only).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    /// If any pattern is a substring of the requested shell line, deny.
    #[serde(default)]
    pub deny_substrings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default = "default_authorized_keys")]
    pub authorized_keys_path: PathBuf,
    /// When true, accept plain TCP with frames (development only).
    #[serde(default)]
    pub allow_insecure_plain: bool,
    /// If set (e.g. `127.0.0.1:18443`), listen for **plaintext** frames here when `allow_insecure_plain` is true.
    #[serde(default)]
    pub insecure_plain_listen: Option<String>,
    #[serde(default)]
    pub policy: PolicyConfig,
    /// `bash -lc` by default.
    #[serde(default = "default_shell_argv")]
    pub shell_argv: Vec<String>,
    #[serde(default = "default_exec_timeout_secs")]
    pub exec_timeout_secs: u64,
    #[serde(default = "default_policy_group")]
    pub policy_group_default: String,
    /// Hex fingerprint (64 chars) → policy_group for AuthResult.
    #[serde(default)]
    pub policy_group_by_fingerprint: HashMap<String, String>,
}

fn default_listen() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_authorized_keys() -> PathBuf {
    PathBuf::from("/etc/sao/authorized_keys")
}

fn default_shell_argv() -> Vec<String> {
    vec!["bash".to_string(), "-lc".to_string()]
}

fn default_exec_timeout_secs() -> u64 {
    300
}

fn default_policy_group() -> String {
    "default".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            tls: TlsConfig::default(),
            authorized_keys_path: default_authorized_keys(),
            allow_insecure_plain: false,
            insecure_plain_listen: None,
            policy: PolicyConfig::default(),
            shell_argv: default_shell_argv(),
            exec_timeout_secs: default_exec_timeout_secs(),
            policy_group_default: default_policy_group(),
            policy_group_by_fingerprint: HashMap::new(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, crate::CoreError> {
        let raw = std::fs::read_to_string(path)?;
        let c: ServerConfig = serde_yaml::from_str(&raw)?;
        Ok(c)
    }
}
