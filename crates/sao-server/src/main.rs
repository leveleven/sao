//! sao-server: TLS (default) + optional plaintext dev listener.

mod session;
mod tls_util;

use std::sync::Arc;

use clap::Parser;
use sao_core::config::ServerConfig;
use sao_core::FrameCodec;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "sao-server")]
struct Args {
    /// Path to YAML config.
    #[arg(long, default_value = "config.yaml")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = if args.config.exists() {
        ServerConfig::load(&args.config)?
    } else {
        tracing::warn!(path = %args.config.display(), "config missing, using defaults");
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
