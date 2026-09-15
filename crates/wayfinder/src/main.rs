use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{collections::BTreeSet, sync::Arc};
use std::{
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;
use wayfinder_core::credentials::{Capability, CredentialStore};
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
        /// Enable authenticated HTTP MCP (TLS is provided by a reverse proxy).
        #[arg(long)]
        mcp_enabled: bool,
        /// Canonical HTTPS origin for installation-local OAuth (no trailing slash).
        #[arg(long)]
        mcp_public_url: Option<String>,
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
    /// Manage MCP credentials through the running daemon (local administrator only).
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}
#[derive(Subcommand)]
enum AuthCommand {
    /// List registered OAuth client metadata, excluding secrets.
    OauthClients,
    /// Revoke an OAuth client and all its grants.
    OauthRevokeClient { name: String },
    /// Pre-register a confidential OAuth client; displays its secret once.
    OauthRegister {
        name: String,
        #[arg(long)]
        redirect_uri: String,
    },
    /// Show pending browser requests and their exact redirects/scopes.
    Pending,
    /// Approve a request you initiated. Defaults to read only; return to browser.
    Approve {
        id: String,
        #[arg(long)]
        name: String,
        #[arg(long, value_delimiter = ',', default_value = "read", value_parser = ["read", "exec"])]
        permissions: Vec<String>,
    },
    /// Create a credential and display its secret once. Defaults to read only.
    Create {
        name: String,
        #[arg(long, value_delimiter = ',', default_value = "read", value_parser = ["read", "exec"])]
        permissions: Vec<String>,
    },
    /// List metadata; never displays secrets or verifiers. Times are Unix seconds.
    List,
    /// Revoke by name immediately for subsequent requests.
    Revoke { name: String },
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
            mcp_enabled,
            mcp_public_url,
            peer_listen,
            peer_advertise,
        } => {
            let _lock = lock_dir(&data)?;
            ensure!(
                !data.join("config.json").exists(),
                "Configuration already exists"
            );
            let mut c = Config::new(
                name,
                mcp_listen,
                peer_listen,
                peer_advertise.unwrap_or(peer_listen),
            )?;
            c.mcp_enabled = mcp_enabled;
            c.mcp_public_url = mcp_public_url;
            c.validate()?;
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
        Command::Auth { command } => {
            use wayfinder_api::Operation;
            let client = wayfinder_api::Client::attach(&data)?;
            match command {
                AuthCommand::OauthClients => println!(
                    "{}",
                    serde_json::to_string_pretty(&client.call(Operation::OauthClients).await?)?
                ),
                AuthCommand::OauthRevokeClient { name } => {
                    client.call(Operation::OauthRevokeClient { name }).await?;
                    println!("OAuth client and grants revoked.");
                }
                AuthCommand::OauthRegister { name, redirect_uri } => {
                    let value = client
                        .call(Operation::OauthRegister { name, redirect_uri })
                        .await?;
                    println!(
                        "Client ID: {}\nClient secret: {}\n\nSave the client secret now. It will not be shown again.",
                        value["client"]["id"]
                            .as_str()
                            .context("Missing client ID")?,
                        value["client_secret"]
                            .as_str()
                            .context("Missing client secret")?
                    );
                }
                AuthCommand::Pending => println!(
                    "{}",
                    serde_json::to_string_pretty(&client.call(Operation::OauthPending).await?)?
                ),
                AuthCommand::Approve {
                    id,
                    name,
                    permissions,
                } => {
                    let permissions = permissions
                        .iter()
                        .map(|p| {
                            if p == "read" {
                                Capability::Read
                            } else {
                                Capability::Exec
                            }
                        })
                        .collect();
                    client
                        .call(Operation::OauthApprove {
                            id,
                            name,
                            permissions,
                        })
                        .await?;
                    println!(
                        "Approved. Refresh the authorization page to return to your MCP client."
                    );
                }
                AuthCommand::Create { name, permissions } => {
                    let permissions: BTreeSet<_> = permissions
                        .iter()
                        .map(|p| {
                            if p == "read" {
                                Capability::Read
                            } else {
                                Capability::Exec
                            }
                        })
                        .collect();
                    let value = client
                        .call(Operation::AuthCreate {
                            name: name.clone(),
                            permissions,
                        })
                        .await?;
                    let token = value["token"]
                        .as_str()
                        .context("Missing generated credential")?;
                    println!(
                        "Created credential: {name}\n\nToken:\n{token}\n\nSave this token now. It will not be shown again."
                    );
                }
                AuthCommand::List => println!(
                    "{}",
                    serde_json::to_string_pretty(&client.call(Operation::AuthList).await?)?
                ),
                AuthCommand::Revoke { name } => {
                    client
                        .call(Operation::AuthRevoke { name: name.clone() })
                        .await?;
                    println!("Revoked credential: {name}");
                }
            }
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
    let credentials = Arc::new(CredentialStore::open(data.join("credentials.json"))?);
    let oauth = config
        .mcp_public_url
        .clone()
        .map(|issuer| wayfinder_core::oauth::OAuth::new(issuer, credentials.clone()).map(Arc::new))
        .transpose()?;
    let mcp = if config.mcp_enabled {
        Some(
            TcpListener::bind(config.mcp_listen)
                .await
                .context("Cannot bind MCP listener")?,
        )
    } else {
        None
    };
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
    #[cfg(any(target_os = "linux", windows))]
    {
        let applications = wayfinder_network::applications::Endpoint::bind()?;
        services.spawn(network.clone().serve_applications(applications));
    }
    if let Some(mcp) = mcp {
        services.spawn(wayfinder_mcp::serve(
            mcp,
            network.clone(),
            credentials.clone(),
            oauth.clone(),
        ));
    }
    services.spawn(wayfinder_api::serve(
        control,
        network.clone(),
        descriptor.credential,
        credentials,
        oauth,
    ));
    services.spawn(network.serve(peer));
    eprintln!(
        "Wayfinder daemon listening: MCP enabled={} address={}, peers {}",
        config.mcp_enabled, config.mcp_listen, config.peer_listen
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
