//! TLS via native-tls: accept self-signed, then enforce SPKI pin on peer cert.

use std::io::{Error as IoError, ErrorKind};

use native_tls::TlsConnector;
use sao_core::spki::spki_sha256_bytes_from_cert_der;
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as TokioTls;

/// Connect to `host:port`, require peer cert SPKI SHA-256 == `pin`.
pub async fn connect_pinned(
    host: &str,
    port: u16,
    pin: &[u8; 32],
) -> Result<tokio_native_tls::TlsStream<TcpStream>, IoError> {
    let tcp = TcpStream::connect((host, port)).await?;
    let cx = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(IoError::other)?;
    let cx = TokioTls::from(cx);
    let tls = cx.connect(host, tcp).await.map_err(IoError::other)?;
    let der = tls
        .get_ref()
        .peer_certificate()
        .map_err(IoError::other)?
        .ok_or_else(|| IoError::new(ErrorKind::PermissionDenied, "no peer certificate"))?;
    let cert_der = der.to_der().map_err(IoError::other)?;
    let got = spki_sha256_bytes_from_cert_der(&cert_der)
        .map_err(|e| IoError::new(ErrorKind::InvalidData, format!("cert parse: {e}")))?;
    if &got != pin {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "TLS SPKI pin mismatch (possible MITM or wrong known_hosts)",
        ));
    }
    Ok(tls)
}

/// Connect without pin check; use only to read presented cert fingerprint.
pub async fn connect_probe(host: &str, port: u16) -> Result<Vec<u8>, IoError> {
    let tcp = TcpStream::connect((host, port)).await?;
    let cx = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(IoError::other)?;
    let cx = TokioTls::from(cx);
    let tls = cx.connect(host, tcp).await.map_err(IoError::other)?;
    let c = tls
        .get_ref()
        .peer_certificate()
        .map_err(IoError::other)?
        .ok_or_else(|| IoError::other("no peer certificate"))?;
    c.to_der().map_err(IoError::other)
}
