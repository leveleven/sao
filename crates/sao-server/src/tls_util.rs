//! Load or generate TLS PEM for rustls server.

use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sao_core::config::TlsConfig;
use sao_core::spki::spki_sha256_hex_from_pem;
use sao_core::CoreError;
use tracing::info;

pub fn ensure_self_signed_pem(tls: &TlsConfig) -> Result<(), CoreError> {
    if tls.cert_path.exists() && tls.key_path.exists() {
        return Ok(());
    }
    if !tls.auto_generate_self_signed {
        return Err(CoreError::Io(std::io::Error::new(
            ErrorKind::NotFound,
            format!(
                "TLS cert/key missing and auto_generate_self_signed=false: {:?} {:?}",
                tls.cert_path, tls.key_path
            ),
        )));
    }
    if let Some(p) = tls.cert_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    if let Some(p) = tls.key_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let gen = rcgen::generate_simple_self_signed([
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .map_err(|e| CoreError::Io(std::io::Error::other(e)))?;
    let cert_pem = gen.cert.pem();
    let key_pem = gen.key_pair.serialize_pem();
    std::fs::write(&tls.cert_path, &cert_pem)?;
    std::fs::write(&tls.key_path, key_pem)?;
    Ok(())
}

pub fn print_spki_fingerprint(cert_pem: &str) -> Result<(), CoreError> {
    let fp = spki_sha256_hex_from_pem(cert_pem)?;
    info!(target: "sao::audit", event = "tls_spki_fingerprint", fingerprint = %fp, "pin this host:port in client known_hosts");
    eprintln!("sao-server TLS SPKI SHA256 (pin): {fp}");
    Ok(())
}

pub fn rustls_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, CoreError> {
    ensure_self_signed_pem(tls)?;
    let cert_pem = std::fs::read_to_string(&tls.cert_path)?;
    print_spki_fingerprint(&cert_pem)?;
    let mut cert_r = BufReader::new(File::open(&tls.cert_path)?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_r)
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(CoreError::Io(std::io::Error::new(
            ErrorKind::InvalidData,
            "no certificates in PEM",
        )));
    }
    let mut key_r = BufReader::new(File::open(&tls.key_path)?);
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_r)
        .next()
        .transpose()
        .map_err(|e| CoreError::Io(std::io::Error::new(ErrorKind::InvalidData, e)))?
        .ok_or_else(|| {
            CoreError::Io(std::io::Error::new(
                ErrorKind::InvalidData,
                "no PKCS8 private key",
            ))
        })?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .map_err(|e| CoreError::Io(std::io::Error::new(ErrorKind::InvalidData, e)))?;
    Ok(Arc::new(config))
}
