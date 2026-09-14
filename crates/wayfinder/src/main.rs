use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
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
    /// Attach to a live daemon, or run one until this TUI exits.
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
        Command::Daemon => {
            let lock = lock_dir(&data)?;
            let shutdown = CancellationToken::new();
            let runner = daemon(data, lock, shutdown.clone());
            tokio::pin!(runner);
            let signal = tokio::select! {
                result = &mut runner => return result,
                result = stop_signal() => result,
            };
            shutdown.cancel();
            combine_results(signal, runner.await)?;
        }
        Command::Token => {
            let c: Config = read_private(&data.join("config.json"))?;
            c.validate()?;
            println!("{}", c.mcp_token);
        }
        Command::Tui => tui(data).await?,
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
// Probe the authenticated API, never just the discovery file. Bound stale endpoints.
async fn live_client(data: &Path) -> Result<wayfinder_api::Client> {
    let client = wayfinder_api::Client::attach(data)?;
    tokio::time::timeout(Duration::from_millis(500), client.status())
        .await
        .context("Daemon control status timed out")??;
    Ok(client)
}

async fn wait_for_control(data: &Path) -> Result<wayfinder_api::Client> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(client) = live_client(data).await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("Daemon control interface was not ready within 5 seconds")
}

fn combine_results(result: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("Daemon cleanup also failed: {cleanup:#}")))
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

async fn tui(data: PathBuf) -> Result<()> {
    let signal = stop_signal();
    tokio::pin!(signal);
    let existing = tokio::select! {
        result = live_client(&data) => result,
        result = &mut signal => return result,
    };
    let lock = match existing {
        Ok(client) => {
            return tokio::select! {
                result = wayfinder_tui::run(client, false) => result,
                result = &mut signal => result,
            };
        }
        Err(_) => match lock_dir(&data) {
            Ok(lock) => lock,
            Err(error) => {
                // Another starter may hold the lock before publishing discovery.
                // Never start services or change its descriptor in this case.
                let client = tokio::select! {
                    result = wait_for_control(&data) => result.with_context(|| format!("Cannot start daemon: {error:#}"))?,
                    result = &mut signal => return result,
                };
                return tokio::select! {
                    result = wayfinder_tui::run(client, false) => result,
                    result = &mut signal => result,
                };
            }
        },
    };
    let shutdown = CancellationToken::new();
    let mut runner = tokio::spawn(daemon(data.clone(), lock, shutdown.clone()));
    let session = async {
        let client = wait_for_control(&data).await?;
        wayfinder_tui::run(client, true).await
    };
    let result = tokio::select! {
        result = &mut runner => {
            return result.context("Daemon task failed")?
                .and_then(|()| anyhow::bail!("Daemon stopped while the TUI was running"));
        }
        result = session => result,
        result = &mut signal => result,
    };
    shutdown.cancel();
    combine_results(
        result,
        runner.await.context("Daemon task failed").and_then(|r| r),
    )
}

struct DescriptorCleanup(PathBuf);
impl Drop for DescriptorCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn daemon(data: PathBuf, _lock: File, shutdown: CancellationToken) -> Result<()> {
    let config: Config = read_private(&data.join("config.json"))
        .context("Initialize first with wayfinder init --name NAME")?;
    config.validate()?;
    let identity: Identity = read_private(&data.join("identity.json"))
        .context("Durable identity is missing or invalid; restore this node's private backup")?;
    let network = wayfinder_network::Network::new(
        config.clone(),
        identity,
        data.join("state.json"),
        shutdown.clone(),
    )?;
    // Bind the administration and peer listeners before publishing discovery.
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
    let applications = wayfinder_network::applications::Endpoint::bind()?;
    services.spawn(network.clone().serve_applications(applications));
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
    let outcome = tokio::select! {r=services.join_next()=>match r{Some(Ok(r))=>r,Some(Err(e))=>Err(e.into()),None=>Ok(())},_=shutdown.cancelled()=>Ok(())};
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
    let cleanup = drained
        .context("Daemon services did not stop within 5 seconds")
        .and_then(|r| r);
    let cleanup = combine_results(
        cleanup,
        std::fs::remove_file(data.join("control.json"))
            .context("Cannot remove daemon control descriptor"),
    );
    combine_results(outcome, cleanup)
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
