//! Client `~/.sao/known_hosts`: one line per `host port spki_sha256_hex`.

use std::collections::HashMap;
use std::path::Path;

use crate::CoreError;

#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    /// Normalized host (lowercase hostname; IP as-is), port → 32-byte SPKI SHA-256.
    pins: HashMap<(String, u16), [u8; 32]>,
}

impl KnownHosts {
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let mut k = Self::default();
        if !path.exists() {
            return Ok(k);
        }
        let s = std::fs::read_to_string(path)?;
        for (lineno, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                return Err(CoreError::KnownHostsLine(format!(
                    "line {}: need host port fingerprint",
                    lineno + 1
                )));
            }
            let host = normalize_host(parts[0]);
            let port: u16 = parts[1]
                .parse()
                .map_err(|_| CoreError::KnownHostsLine(format!("line {}: bad port", lineno + 1)))?;
            let fp = parse_hex32(parts[2])?;
            k.pins.insert((host, port), fp);
        }
        Ok(k)
    }

    pub fn pin_hex(&self, host: &str, port: u16) -> Result<[u8; 32], CoreError> {
        let host = normalize_host(host);
        let key = (host.clone(), port);
        self.pins
            .get(&key)
            .copied()
            .ok_or_else(|| CoreError::KnownHostsMissing(format!("{}:{port}", key.0)))
    }

    pub fn insert_hex(&mut self, host: &str, port: u16, hex_fp: &str) -> Result<(), CoreError> {
        let fp = parse_hex32(hex_fp)?;
        self.pins.insert((normalize_host(host), port), fp);
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<(), CoreError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut lines: Vec<String> = vec!["# sao known_hosts: host port spki_sha256_hex".into()];
        let mut keys: Vec<_> = self.pins.keys().cloned().collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (host, port) in keys {
            let fp = hex::encode(self.pins[&(host.clone(), port)]);
            lines.push(format!("{host} {port} {fp}"));
        }
        lines.push(String::new());
        std::fs::write(path, lines.join("\n"))?;
        Ok(())
    }
}

fn normalize_host(h: &str) -> String {
    let h = h.trim_matches(&['[', ']'][..]);
    if h.contains(':')
        && !h
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
    {
        // IPv6 without brackets
        return h.to_lowercase();
    }
    h.to_lowercase()
}

fn parse_hex32(s: &str) -> Result<[u8; 32], CoreError> {
    let s = s.trim().to_lowercase();
    if s.len() != 64 {
        return Err(CoreError::InvalidFingerprint(s));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| CoreError::InvalidFingerprint(s.clone()))?;
        out[i] = byte;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn roundtrip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        let mut k = KnownHosts::default();
        k.insert_hex("127.0.0.1", 8443, &"a".repeat(64)).unwrap();
        k.save(&p).unwrap();
        let k2 = KnownHosts::load(&p).unwrap();
        let pin = k2.pin_hex("127.0.0.1", 8443).unwrap();
        assert_eq!(pin, [0xaa; 32]);
    }

    #[test]
    fn parse_line_uppercase_hex() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "example.com 443 {}", "b".repeat(64)).unwrap();
        let k = KnownHosts::load(&p).unwrap();
        assert!(k.pin_hex("example.com", 443).is_ok());
    }
}
