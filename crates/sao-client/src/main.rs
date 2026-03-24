//! sao CLI: TLS + SPKI pin, Agent Ed25519 auth, remote shell.

mod connect;

use std::io::{self, IsTerminal, Write};
use std::path::Path;

use base64::Engine;
use clap::{Parser, Subcommand};
use sao_core::agent_key::{load_or_create_signing_key, public_key_path, sign_auth_message};
use sao_core::authorized_keys::ed25519_fingerprint_hex;
use sao_core::known_hosts::KnownHosts;
use sao_core::signing_bytes;
use sao_core::spki::spki_sha256_hex_from_cert_der;
use sao_core::{msg_type, CoreError, FrameCodec};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Parser, Debug)]
#[command(name = "sao")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a remote shell command (TLS pin + auth).
    Run {
        /// TCP port (default 8443). Place `-p` right after `run`, before `HOST`.
        #[arg(
            short = 'p',
            long = "port",
            default_value_t = 8443,
            value_name = "PORT"
        )]
        port: u16,
        /// Hostname or IP (no `:port` suffix; use `-p`).
        host: String,
        #[arg(required = true, num_args = 1..)]
        cmd: Vec<String>,
        /// If `host:port` has no pin in known_hosts, save the server SPKI automatically (MITM risk on untrusted networks).
        #[arg(long = "accept-new")]
        accept_new: bool,
    },
    /// Print server SPKI fingerprint (use only on a trusted network).
    TrustProbe { addr: String },
    /// `sao trust add HOST PORT <64-hex>`
    TrustAdd {
        host: String,
        port: u16,
        fingerprint_hex: String,
    },
    /// Show agent fingerprint, write `agent.ed25519.pub`, print authorized_keys line.
    KeyFingerprint,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let home = dirs::home_dir().ok_or("no home")?;
    let sao_dir = home.join(".sao");
    let known_path = sao_dir.join("known_hosts");
    let key_path = sao_dir.join("keys").join("agent.ed25519");

    match cli.cmd {
        Cmd::TrustAdd {
            host,
            port,
            fingerprint_hex,
        } => {
            let mut kh = KnownHosts::load(&known_path)?;
            kh.insert_hex(&host, port, &fingerprint_hex)?;
            kh.save(&known_path)?;
            eprintln!("pinned {host}:{port}");
        }
        Cmd::TrustProbe { addr } => {
            let (host, port) = parse_addr(&addr)?;
            let der = connect::connect_probe(&host, port).await?;
            let fp = spki_sha256_hex_from_cert_der(&der)?;
            println!("{fp}");
            eprintln!("If correct: sao trust add {host} {port} {fp}");
        }
        Cmd::KeyFingerprint => {
            let sk = load_or_create_signing_key(&key_path)?;
            let fp = ed25519_fingerprint_hex(&sk.verifying_key());
            let pub_path = public_key_path(&key_path);
            println!("{fp}");
            eprintln!("Keys: {} and {}", key_path.display(), pub_path.display());
            eprintln!("Append the non-comment line from the .pub file to the server's authorized_keys.");
        }
        Cmd::Run {
            port,
            host,
            cmd,
            accept_new,
        } => {
            let shell_line = cmd.join(" ");
            let tls = connect_with_pin_management(
                &host,
                port,
                &known_path,
                accept_new,
            )
            .await?;
            run_session(tls, &key_path, &shell_line).await?;
        }
    }
    Ok(())
}

/// Connect with pin from known_hosts; on mismatch, prompt to replace (or use --accept-new).
async fn connect_with_pin_management(
    host: &str,
    port: u16,
    known_path: &Path,
    accept_new: bool,
) -> Result<
    tokio_native_tls::TlsStream<tokio::net::TcpStream>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let pin = resolve_tls_pin(host, port, known_path, accept_new).await?;
    match connect::connect_pinned(host, port, &pin).await {
        Ok(tls) => Ok(tls),
        Err(e) if e.to_string().contains("SPKI pin mismatch") => {
            let der = connect::connect_probe(host, port)
                .await
                .map_err(|e| format!("TLS connect (host key changed): {e}"))?;
            let fp_hex = spki_sha256_hex_from_cert_der(&der)
                .map_err(|e| format!("server certificate: {e}"))?;

            let replace = if accept_new {
                eprintln!(
                    "Warning: replacing TLS pin for {host}:{port} with new SPKI SHA-256 {fp_hex} — verify on a trusted network."
                );
                true
            } else if io::stdin().is_terminal() {
                eprintln!("Host key for {host}:{port} has changed.");
                eprintln!("New TLS SPKI SHA-256 fingerprint is {fp_hex}.");
                eprint!("Replace the pin in known_hosts? (yes/no): ");
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
            } else {
                return Err(format!(
                    "TLS pin mismatch for {host}:{port}. Run interactively to replace, or: sao trust add {host} {port} {fp_hex}"
                )
                .into());
            };

            if !replace {
                return Err("Host key not accepted.".into());
            }

            let mut kh = KnownHosts::load(known_path)?;
            kh.insert_hex(host, port, &fp_hex)?;
            kh.save(known_path)?;
            eprintln!("Replaced pin for {host}:{port} in {}", known_path.display());
            let new_pin = kh.pin_hex(host, port)?;
            connect::connect_pinned(host, port, &new_pin)
                .await
                .map_err(|e| e.to_string().into())
        }
        Err(e) => Err(e.to_string().into()),
    }
}

/// Load SPKI pin from known_hosts, or trust-on-first-use via `--accept-new`, TTY prompt, or error with hint.
async fn resolve_tls_pin(
    host: &str,
    port: u16,
    known_path: &Path,
    accept_new: bool,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let mut kh = KnownHosts::load(known_path)?;
    match kh.pin_hex(host, port) {
        Ok(pin) => Ok(pin),
        Err(CoreError::KnownHostsMissing(_)) => {
            let der = connect::connect_probe(host, port)
                .await
                .map_err(|e| format!("TLS connect (trust setup): {e}"))?;
            let fp_hex = spki_sha256_hex_from_cert_der(&der)
                .map_err(|e| format!("server certificate: {e}"))?;

            let save = if accept_new {
                eprintln!(
                    "Warning: saving new TLS pin for {host}:{port} (SPKI SHA-256 {fp_hex}) — verify on a trusted network when possible."
                );
                true
            } else if io::stdin().is_terminal() {
                eprintln!("The authenticity of host '{host}' (port {port}) can't be established.");
                eprintln!("TLS SPKI SHA-256 fingerprint is {fp_hex}.");
                eprint!("Are you sure you want to continue connecting (yes/no)? ");
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
            } else {
                return Err(format!(
                    "no TLS pin for {host}:{port}. Add with:\n  sao trust add {host} {port} {fp_hex}\n\
                     Or non-interactively:\n  sao run -p {port} --accept-new {host} -- …"
                )
                .into());
            };

            if !save {
                return Err("Host key not accepted.".into());
            }

            kh.insert_hex(host, port, &fp_hex)?;
            kh.save(known_path)?;
            eprintln!("Pinned {host}:{port} in {}", known_path.display());
            Ok(kh.pin_hex(host, port)?)
        }
        Err(e) => Err(e.into()),
    }
}

fn parse_addr(s: &str) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.starts_with('[') {
        let end = s
            .find("]:")
            .ok_or_else(|| "expected [ipv6]:port".to_string())?;
        let host = s[1..end].to_string();
        let port: u16 = s[end + 2..].parse().map_err(|_| "bad port".to_string())?;
        return Ok((host, port));
    }
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| "expected host:port".to_string())?;
    if h.is_empty() {
        return Err("empty host".into());
    }
    let port: u16 = p.parse().map_err(|_| "bad port".to_string())?;
    Ok((h.to_string(), port))
}

#[derive(Deserialize)]
struct AuthChallenge {
    nonce: String,
    session_id: String,
}

#[derive(Deserialize)]
struct AuthResult {
    ok: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

async fn run_session<S>(
    stream: S,
    key_path: &Path,
    shell_line: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let sk = load_or_create_signing_key(key_path)?;
    let fp = ed25519_fingerprint_hex(&sk.verifying_key());
    let mut codec = FrameCodec::new(stream);

    let f = codec.read_frame().await?;
    if f.msg_type != msg_type::AUTH_CHALLENGE {
        return Err("expected AuthChallenge".into());
    }
    let ch: AuthChallenge = serde_json::from_slice(&f.payload)?;
    let nonce = base64::engine::general_purpose::STANDARD.decode(&ch.nonce)?;
    let msg = signing_bytes(&nonce, &ch.session_id);
    let sig = sign_auth_message(&sk, &msg);
    let resp = json!({
        "key_type": sao_core::KEY_TYPE_ED25519,
        "fingerprint": fp,
        "signature": sig,
    });
    codec
        .write_frame(msg_type::AUTH_RESPONSE, &serde_json::to_vec(&resp)?)
        .await?;

    let f = codec.read_frame().await?;
    if f.msg_type != msg_type::AUTH_RESULT {
        return Err("expected AuthResult".into());
    }
    let ar: AuthResult = serde_json::from_slice(&f.payload)?;
    if !ar.ok {
        let reason = ar.reason.as_deref().unwrap_or("");
        let detail = ar.message.as_deref().unwrap_or("");
        if reason == "UNKNOWN_KEY"
            || detail.contains("authorized_keys")
            || detail.contains("fingerprint not in authorized_keys")
        {
            return Err(format!(
                "Authentication rejected: this agent's public key is not in the server's authorized_keys.\n\
                 Run `sao key-fingerprint` to create or refresh your key pair; append the non-comment line from ~/.sao/keys/agent.ed25519.pub to the server's authorized_keys.\n\
                 Server detail: {reason} {detail:?}"
            )
            .into());
        }
        return Err(format!("auth failed: {} {:?}", reason, ar.message).into());
    }

    let exec = json!({ "shell": shell_line });
    codec
        .write_frame(msg_type::EXEC_SHELL, &serde_json::to_vec(&exec)?)
        .await?;

    loop {
        let f = codec.read_frame().await?;
        match f.msg_type {
            msg_type::STREAM_STDOUT | msg_type::STREAM_STDERR => {
                let v: serde_json::Value = serde_json::from_slice(&f.payload)?;
                let data = v
                    .get("data")
                    .and_then(|x| x.as_str())
                    .ok_or("bad stream frame")?;
                let raw = base64::engine::general_purpose::STANDARD.decode(data)?;
                use std::io::Write;
                if f.msg_type == msg_type::STREAM_STDERR {
                    std::io::stderr().write_all(&raw)?;
                } else {
                    std::io::stdout().write_all(&raw)?;
                }
            }
            msg_type::EXEC_EXIT => {
                let v: serde_json::Value = serde_json::from_slice(&f.payload)?;
                let code = v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(-1);
                std::process::exit(code as i32);
            }
            msg_type::POLICY_DENIED => {
                eprintln!("{}", String::from_utf8_lossy(&f.payload));
                std::process::exit(126);
            }
            msg_type::ERROR => {
                eprintln!("{}", String::from_utf8_lossy(&f.payload));
                std::process::exit(1);
            }
            _ => {
                eprintln!("unexpected msg_type 0x{:02x}", f.msg_type);
                std::process::exit(1);
            }
        }
    }
}
