//! One client session: auth then exec loop.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rand::RngCore;
use sao_core::authorized_keys::{find_key, load_authorized_keys, verify_ed25519_signature};
use sao_core::config::ServerConfig;
use sao_core::policy::check_shell;
use sao_core::signing_bytes;
use sao_core::CoreError;
use sao_core::{msg_type, FrameCodec};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::process::Command;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct AuthChallengePayload {
    nonce: String,
    session_id: String,
}

#[derive(Serialize, Deserialize)]
struct AuthResponsePayload {
    key_type: String,
    fingerprint: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct ExecShellPayload {
    shell: String,
}

pub async fn run_session<S>(
    mut codec: FrameCodec<S>,
    config: Arc<ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let keys = load_authorized_keys(&config.authorized_keys_path)
        .map_err(|e| format!("authorized_keys: {e}"))?;

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let session_id = Uuid::new_v4().to_string();
    let challenge = AuthChallengePayload {
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        session_id: session_id.clone(),
    };
    let ch_json = serde_json::to_vec(&challenge)?;
    codec
        .write_frame(msg_type::AUTH_CHALLENGE, &ch_json)
        .await?;

    let resp = codec.read_frame().await?;
    if resp.msg_type != msg_type::AUTH_RESPONSE {
        send_error(
            &mut codec,
            "EXPECTED_AUTH_RESPONSE",
            "expected AuthResponse",
        )
        .await?;
        return Ok(());
    }
    let ar: AuthResponsePayload = serde_json::from_slice(&resp.payload)?;
    if ar.key_type != sao_core::KEY_TYPE_ED25519 {
        send_auth_fail(&mut codec, "UNSUPPORTED_KEY_TYPE", "only sao-ed25519").await?;
        return Ok(());
    }
    let msg = signing_bytes(&nonce, &session_id);
    let entry = match find_key(&keys, &ar.fingerprint) {
        Some(k) => k,
        None => {
            send_auth_fail(
                &mut codec,
                "UNKNOWN_KEY",
                "fingerprint not in authorized_keys",
            )
            .await?;
            tracing::warn!(target: "sao::audit", session_id = %session_id, fingerprint = %ar.fingerprint, ok = false, "auth failed");
            return Ok(());
        }
    };
    if let Err(e) = verify_ed25519_signature(&entry.verifying_key, &msg, &ar.signature) {
        send_auth_fail(&mut codec, "BAD_SIGNATURE", &e.to_string()).await?;
        tracing::warn!(target: "sao::audit", session_id = %session_id, ok = false, reason = "BAD_SIGNATURE");
        return Ok(());
    }
    let policy_group = config
        .policy_group_by_fingerprint
        .get(&entry.fingerprint_hex.to_lowercase())
        .cloned()
        .unwrap_or_else(|| config.policy_group_default.clone());
    let agent_name = if entry.comment.is_empty() {
        None
    } else {
        Some(entry.comment.clone())
    };
    let ok_json = json!({
        "ok": true,
        "agent_name": agent_name,
        "policy_group": policy_group,
    });
    codec
        .write_frame(msg_type::AUTH_RESULT, &serde_json::to_vec(&ok_json)?)
        .await?;
    tracing::info!(target: "sao::audit", session_id = %session_id, fingerprint = %entry.fingerprint_hex, ok = true, "auth ok");

    loop {
        let frame = match codec.read_frame().await {
            Ok(f) => f,
            Err(sao_core::ProtocolError::UnexpectedEof) => break,
            Err(e) => return Err(e.into()),
        };
        match frame.msg_type {
            msg_type::EXEC_SHELL => {
                let p: ExecShellPayload = serde_json::from_slice(&frame.payload)?;
                run_one_exec(&mut codec, &config, &session_id, &p.shell).await?;
            }
            _ => {
                send_error(
                    &mut codec,
                    "UNKNOWN_MSG_TYPE",
                    "only ExecShell allowed after auth",
                )
                .await?;
                break;
            }
        }
    }
    Ok(())
}

async fn send_error<S: AsyncRead + AsyncWrite + Unpin>(
    codec: &mut FrameCodec<S>,
    code: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let j = serde_json::to_vec(&json!({ "code": code, "message": message }))?;
    codec.write_frame(msg_type::ERROR, &j).await?;
    Ok(())
}

async fn send_auth_fail<S: AsyncRead + AsyncWrite + Unpin>(
    codec: &mut FrameCodec<S>,
    reason: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let j = serde_json::to_vec(&json!({
        "ok": false,
        "reason": reason,
        "message": message,
    }))?;
    codec.write_frame(msg_type::AUTH_RESULT, &j).await?;
    Ok(())
}

enum StreamChunk {
    Out(Vec<u8>),
    Err(Vec<u8>),
}

async fn run_one_exec<S: AsyncRead + AsyncWrite + Unpin>(
    codec: &mut FrameCodec<S>,
    config: &ServerConfig,
    session_id: &str,
    shell: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Err(CoreError::PolicyDenied(msg)) = check_shell(&config.policy, shell) {
        let j = serde_json::to_vec(&json!({
            "code": "POLICY_DENIED",
            "rule_id": null,
            "message": msg,
        }))?;
        codec.write_frame(msg_type::POLICY_DENIED, &j).await?;
        tracing::warn!(target: "sao::audit", %session_id, event = "policy_denied", shell_preview = %shell.chars().take(80).collect::<String>());
        return Ok(());
    }

    if config.shell_argv.len() < 2 {
        return Err("shell_argv must have at least [program, -lc]".into());
    }
    let prog = &config.shell_argv[0];
    let mut args: Vec<String> = config.shell_argv[1..].to_vec();
    args.push(shell.to_string());

    let mut cmd = Command::new(prog);
    cmd.args(&args);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let mut child = cmd.spawn()?;
    let pid = child.id();
    let out = child.stdout.take().expect("stdout");
    let err = child.stderr.take().expect("stderr");

    let (tx, mut rx) = mpsc::unbounded_channel::<StreamChunk>();
    let tx_o = tx.clone();
    tokio::spawn(async move {
        let mut r = out;
        let mut buf = vec![0u8; 16384];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_o.send(StreamChunk::Out(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let tx_e = tx;
    tokio::spawn(async move {
        let mut r = err;
        let mut buf = vec![0u8; 16384];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_e.send(StreamChunk::Err(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let timeout = Duration::from_secs(config.exec_timeout_secs.max(1));
    let exec = async {
        loop {
            match rx.recv().await {
                Some(StreamChunk::Out(b)) => {
                    let j = serde_json::to_vec(&json!({
                        "data": base64::engine::general_purpose::STANDARD.encode(&b),
                    }))?;
                    codec.write_frame(msg_type::STREAM_STDOUT, &j).await?;
                }
                Some(StreamChunk::Err(b)) => {
                    let j = serde_json::to_vec(&json!({
                        "data": base64::engine::general_purpose::STANDARD.encode(&b),
                    }))?;
                    codec.write_frame(msg_type::STREAM_STDERR, &j).await?;
                }
                None => break,
            }
        }
        let status = child.wait().await?;
        let code = status.code().unwrap_or(-1);
        let j = serde_json::to_vec(&json!({ "exit_code": code, "signal": null }))?;
        codec.write_frame(msg_type::EXEC_EXIT, &j).await?;
        tracing::info!(target: "sao::audit", %session_id, exit_code = code, "exec done");
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    match tokio::time::timeout(timeout, exec).await {
        Ok(r) => r?,
        Err(_) => {
            if let Some(p) = pid {
                #[cfg(unix)]
                unsafe {
                    libc::kill(p as i32, libc::SIGKILL);
                }
            }
            let j = serde_json::to_vec(&json!({ "exit_code": 124, "signal": null }))?;
            codec.write_frame(msg_type::EXEC_EXIT, &j).await?;
            tracing::warn!(target: "sao::audit", %session_id, "exec timeout");
        }
    }
    Ok(())
}
