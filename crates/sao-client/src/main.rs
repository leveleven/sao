//! sao CLI: TLS + SPKI pin, Agent Ed25519 auth, remote shell.

mod connect;

use std::path::Path;

use base64::Engine;
use clap::{Parser, Subcommand};
use sao_core::agent_key::{load_or_create_signing_key, sign_auth_message};
use sao_core::authorized_keys::ed25519_fingerprint_hex;
use sao_core::known_hosts::KnownHosts;
use sao_core::signing_bytes;
use sao_core::spki::spki_sha256_hex_from_cert_der;
use sao_core::{msg_type, FrameCodec};
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
        /// e.g. `127.0.0.1:8443`
        addr: String,
        #[arg(required = true, num_args = 1..)]
        cmd: Vec<String>,
    },
    /// Print server SPKI fingerprint (use only on a trusted network).
    TrustProbe { addr: String },
    /// `sao trust add HOST PORT <64-hex>`
    TrustAdd {
        host: String,
        port: u16,
        fingerprint_hex: String,
    },
    /// Show agent fingerprint and authorized_keys line.
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
            println!("{fp}");
            eprintln!("Add to server authorized_keys:");
            eprintln!(
                "sao-ed25519 {} agent-label",
                base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().as_bytes())
            );
        }
        Cmd::Run { addr, cmd } => {
            let shell_line = cmd.join(" ");
            let (host, port) = parse_addr(&addr)?;
            let kh = KnownHosts::load(&known_path)?;
            let pin = kh.pin_hex(&host, port)?;
            let tls = connect::connect_pinned(&host, port, &pin).await?;
            run_session(tls, &key_path, &shell_line).await?;
        }
    }
    Ok(())
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
        return Err(format!(
            "auth failed: {} {:?}",
            ar.reason.unwrap_or_default(),
            ar.message
        )
        .into());
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
