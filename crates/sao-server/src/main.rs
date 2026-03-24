//! sao-server: TLS (default) + optional plaintext dev listener.

mod session;
mod tls_util;

use std::path::Path;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sao_core::config::{ServerConfig, LOCAL_DEV_CONFIG_PATH};
use sao_core::FrameCodec;
use tokio::net::TcpListener;

const AUTHORIZED_KEYS_STUB: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/authorized_keys.example"
));

#[derive(Parser, Debug)]
#[command(name = "sao-server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML config (when no subcommand).
    #[arg(long, default_value = LOCAL_DEV_CONFIG_PATH)]
    config: std::path::PathBuf,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Write dev config, TLS cert/key, and authorized_keys stub; then run with `--config`.
    Init {
        #[arg(long, default_value = LOCAL_DEV_CONFIG_PATH)]
        config: std::path::PathBuf,
        /// Overwrite existing config file.
        #[arg(long)]
        force: bool,
    },
}

fn cmd_init(
    config_path: &Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config_path.exists() && !force {
        return Err(format!(
            "{} already exists (pass --force to overwrite)",
            config_path.display()
        )
        .into());
    }
    let cfg = ServerConfig::init_for_dir(
        config_path
            .parent()
            .unwrap_or_else(|| Path::new(".")),
    );
    cfg.save(config_path)?;
    tls_util::ensure_self_signed_pem(&cfg.tls)?;
    let cert_pem = std::fs::read_to_string(&cfg.tls.cert_path)?;
    tls_util::print_spki_fingerprint(&cert_pem)?;

    let ak = &cfg.authorized_keys_path;
    if ak.exists() {
        tracing::info!(path = %ak.display(), "authorized_keys already exists, not modified");
    } else {
        if let Some(p) = ak.parent() {
            if !p.as_os_str().is_empty() {
                std::fs::create_dir_all(p)?;
            }
        }
        std::fs::write(ak, AUTHORIZED_KEYS_STUB)?;
        tracing::info!(path = %ak.display(), "wrote authorized_keys stub");
    }

    eprintln!(
        "Initialized {} — add sao-ed25519 lines to {}, then: sao-server --config {}",
        config_path.display(),
        ak.display(),
        config_path.display()
    );
    Ok(())
}

async fn run_server(
    config_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = if config_path.exists() {
        ServerConfig::load(config_path)?
    } else {
        tracing::warn!(path = %config_path.display(), "config missing, using defaults");
        ServerConfig::default()
    };
    let config = Arc::new(config);

    let tls_cfg = tls_util::rustls_server_config(&config.tls)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind(&config.listen).await?;
    tracing::info!(addr = %config.listen, "TLS listening");

    if config.allow_insecure_plain {
        if let Some(ref addr) = config.insecure_plain_listen {
            match TcpListener::bind(addr).await {
                Ok(l2) => {
                    tracing::warn!(target: "sao::audit", %addr, "INSECURE plaintext listener");
                    let cfg2 = Arc::clone(&config);
                    tokio::spawn(async move {
                        loop {
                            let Ok((s, _)) = l2.accept().await else {
                                continue;
                            };
                            let c = Arc::clone(&cfg2);
                            tokio::spawn(async move {
                                let codec = FrameCodec::new(s);
                                let _ = session::run_session(codec, c).await;
                            });
                        }
                    });
                }
                Err(e) => tracing::error!(%addr, error = %e, "plain bind failed"),
            }
        }
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let a = acceptor.clone();
        let c = Arc::clone(&config);
        tokio::spawn(async move {
            let tls = match a.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(error = %e, "TLS accept failed");
                    return;
                }
            };
            let codec = FrameCodec::new(tls);
            if let Err(e) = session::run_session(codec, c).await {
                tracing::error!(error = %e, "session error");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Init { config, force }) => cmd_init(&config, force),
        None => run_server(&cli.config).await,
    }
}
