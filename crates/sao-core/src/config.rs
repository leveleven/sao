//! Server YAML config shape (`docs/protocol.md` — values are deployment-specific).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

/// Default YAML path for local dev (`sao-server init` and `sao-server` without `--config`).
pub const LOCAL_DEV_CONFIG_PATH: &str = ".sao/config.yaml";

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

    /// Default layout for local development: all paths under `.sao/` in the process cwd.
    pub fn local_dev_init() -> Self {
        Self::init_for_dir(Path::new(".sao"))
    }

    /// Init layout with paths under `dir`; use 0.0.0.0 for system dirs like /etc/sao.
    pub fn init_for_dir(dir: &std::path::Path) -> Self {
        let dir = dir.to_path_buf();
        let listen = if dir.to_string_lossy().starts_with("/etc") {
            "0.0.0.0:8443".to_string()
        } else {
            "127.0.0.1:8443".to_string()
        };
        Self {
            listen,
            tls: TlsConfig {
                cert_path: dir.join("tls").join("cert.pem"),
                key_path: dir.join("tls").join("key.pem"),
                auto_generate_self_signed: true,
            },
            authorized_keys_path: dir.join("authorized_keys"),
            allow_insecure_plain: false,
            insecure_plain_listen: None,
            policy: PolicyConfig {
                deny_substrings: vec!["rm -rf /".to_string()],
            },
            shell_argv: default_shell_argv(),
            exec_timeout_secs: 120,
            policy_group_default: default_policy_group(),
            policy_group_by_fingerprint: HashMap::new(),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), crate::CoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn local_dev_init_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cfg.yaml");
        let c = ServerConfig::local_dev_init();
        c.save(&path).unwrap();
        let c2 = ServerConfig::load(&path).unwrap();
        assert_eq!(c.listen, c2.listen);
        assert_eq!(c.tls.cert_path, c2.tls.cert_path);
        assert_eq!(c.authorized_keys_path, c2.authorized_keys_path);
        assert_eq!(c.policy.deny_substrings, c2.policy.deny_substrings);
    }
}
