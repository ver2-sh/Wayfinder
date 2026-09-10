use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;
use wayfinder_core::*;
#[derive(Parser)]
#[command(
    version,
    about = "A private, self-hosted network of MCP shell execution nodes"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Initialize private configuration and durable identity. Does not start listeners.
    Init {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "127.0.0.1:3000")]
        mcp_listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:3001")]
        peer_listen: SocketAddr,
        #[arg(long)]
        peer_advertise: Option<SocketAddr>,
    },
    /// Run the persistent daemon in the foreground (suitable for an OS service).
    Daemon,
    /// Attach a Ratatui client to an already running daemon.
    Tui,
    /// Show daemon status through the private control interface.
    Status,
    /// Send one JSON administration operation from stdin through private control.
    Control,
    /// Explicitly print this node's MCP bearer credential for client setup.
    Token,
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Wayfinder: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let cli = Cli::parse();
    let data = cli.data_dir.map(Ok).unwrap_or_else(default_data_dir)?;
    match cli.command {
        Command::Init {
            name,
            mcp_listen,
            peer_listen,
            peer_advertise,
        } => {
            let _lock = lock_dir(&data)?;
            ensure!(
                !data.join("config.json").exists(),
                "Configuration already exists"
            );
            let c = Config::new(
                name,
                mcp_listen,
                peer_listen,
                peer_advertise.unwrap_or(peer_listen),
            )?;
            let _ = load_or_create_identity(&data.join("identity.json"))?;
            ensure!(
                !data.join("state.json").exists(),
                "Existing network state requires recovery, not initialization"
            );
            atomic_write(&data.join("state.json"), &Persistent::default())?;
            atomic_write(&data.join("config.json"), &c)?;
            println!("Initialized {}", data.display());
        }
        Command::Daemon => daemon(data).await?,
        Command::Token => {
            let c: Config = read_private(&data.join("config.json"))?;
            c.validate()?;
            println!("{}", c.mcp_token);
        }
        Command::Tui => wayfinder_tui::run(wayfinder_api::Client::attach(&data)?).await?,
        Command::Status => {
            let client = wayfinder_api::Client::attach(&data)?;
            println!("{}", serde_json::to_string_pretty(&client.status().await?)?);
        }
        Command::Control => {
            let mut input = String::new();
            io::stdin().take(16385).read_to_string(&mut input)?;
            ensure!(input.len() <= 16384, "Control request too large");
            let operation =
                serde_json::from_str(&input).context("Invalid control operation JSON")?;
            let client = wayfinder_api::Client::attach(&data)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&client.call(operation).await?)?
            );
        }
    }
    Ok(())
}
struct DescriptorCleanup(PathBuf);
impl Drop for DescriptorCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn daemon(data: PathBuf) -> Result<()> {
    let _lock = lock_dir(&data)?;
    let config: Config = read_private(&data.join("config.json"))
        .context("Initialize first with wayfinder init --name NAME")?;
    config.validate()?;
    let identity: Identity = read_private(&data.join("identity.json"))
        .context("Durable identity is missing or invalid; restore this node's private backup")?;
    let shutdown = CancellationToken::new();
    let network = wayfinder_network::Network::new(
        config.clone(),
        identity,
        data.join("state.json"),
        shutdown.clone(),
    )?;
    // Bind every listener before publishing a control descriptor or serving any request.
    let mcp = TcpListener::bind(config.mcp_listen)
        .await
        .context("Cannot bind MCP listener")?;
    let peer = TcpListener::bind(config.peer_listen)
        .await
        .context("Cannot bind peer listener")?;
    let control = TcpListener::bind("127.0.0.1:0").await?;
    let descriptor = ControlDescriptor {
        version: VERSION,
        address: control.local_addr()?,
        credential: random_secret(),
    };
    atomic_write(&data.join("control.json"), &descriptor)?;
    let _cleanup = DescriptorCleanup(data.join("control.json"));
    let mut services = JoinSet::new();
    services.spawn(wayfinder_mcp::serve(mcp, network.clone()));
    services.spawn(wayfinder_api::serve(
        control,
        network.clone(),
        descriptor.credential,
    ));
    services.spawn(network.serve(peer));
    eprintln!(
        "Wayfinder daemon listening: MCP {}, peers {}",
        config.mcp_listen, config.peer_listen
    );
    let outcome = tokio::select! {r=services.join_next()=>match r{Some(Ok(r))=>r,Some(Err(e))=>Err(e.into()),None=>Ok(())},r=stop_signal()=>r};
    shutdown.cancel();
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(r) = services.join_next().await {
            r??;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    services.abort_all();
    while services.join_next().await.is_some() {}
    if let Ok(r) = drained {
        r?;
    }
    outcome
}
async fn stop_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
