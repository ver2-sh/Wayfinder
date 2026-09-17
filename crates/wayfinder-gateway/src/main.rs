use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
#[derive(Parser)]
#[command(about = "Self-hostable shared Wayfinder MCP/OAuth gateway")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,
    #[arg(long)]
    public_url: String,
    #[arg(long)]
    data_dir: PathBuf,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    anyhow::ensure!(
        a.listen.ip().is_loopback(),
        "Bind gateway to loopback behind a TLS ingress proxy"
    );
    let _lock = wayfinder_core::lock_dir(&a.data_dir)?;
    let store = Arc::new(wayfinder_core::credentials::CredentialStore::open(
        a.data_dir.join("gateway.sqlite"),
    )?);
    let g = wayfinder_gateway::Gateway::new(a.public_url, store)?;
    let maintenance = g.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            if maintenance.expire().is_err() {
                eprintln!("Gateway state expiry failed");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(a.listen).await?;
    eprintln!("Wayfinder gateway listening on {}", a.listen);
    axum::serve(listener, g.router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
