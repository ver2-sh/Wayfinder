use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
};
use wayfinder_core::{identity::*, protocol::Operation, *};
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(
    version,
    about = "Accountless Sync Chain agent: outbound shell access through your gateway"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Create or join a Sync Chain; recovery secrets never belong in arguments.
    Chain {
        #[command(subcommand)]
        command: ChainCommand,
    },
    /// Run the outbound agent as this OS user. Remote commands have the same privileges.
    Daemon,
    Status,
    /// Live terminal view of chain/device/gateway connection status.
    Tui,
    Devices,
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Inspect and explicitly approve a browser OAuth pairing request.
    Authorize {
        code: String,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Explicitly register this same identity at another gateway. Stop the agent first.
    Gateway {
        url: String,
    },
}
#[derive(Subcommand)]
enum ChainCommand {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long,default_value=DEFAULT_GATEWAY)]
        gateway: String,
    },
    Join {
        #[arg(long)]
        name: String,
        #[arg(long,default_value=DEFAULT_GATEWAY)]
        gateway: String,
        #[arg(long)]
        admin: bool,
        #[arg(long)]
        phrase_stdin: bool,
    },
    Show,
}
#[derive(Subcommand)]
enum DeviceCommand {
    Revoke { id: String },
}
#[derive(Subcommand)]
enum AuthCommand {
    List,
    Revoke { id: String },
}
fn load(data: &std::path::Path) -> Result<Installation> {
    let i: Installation = read_private(&data.join("installation.json")).context(
        "No valid device identity; create/join a chain or restore a private device backup",
    )?;
    i.validate()?;
    Ok(i)
}
fn display(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
fn confirm(prompt: &str) -> Result<()> {
    ensure!(
        io::stdin().is_terminal(),
        "Explicit approval requires an interactive terminal"
    );
    eprint!("{prompt} Type yes: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    ensure!(answer.trim() == "yes", "Not approved");
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Wayfinder: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let c = Cli::parse();
    let data = c.data_dir.map(Ok).unwrap_or_else(default_data_dir)?;
    match c.command {
        Command::Chain {
            command: ChainCommand::Create { name, gateway },
        } => {
            let _lock = lock_dir(&data)?;
            ensure!(
                !data.join("installation.json").exists(),
                "An installation already exists"
            );
            validate_gateway(&gateway)?;
            valid_name(&name)?;
            ensure!(
                io::stdout().is_terminal() && io::stdin().is_terminal(),
                "Chain creation requires a private interactive terminal; recovery phrase output cannot be redirected"
            );
            let mut entropy = Zeroizing::new([0u8; 32]);
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(entropy.as_mut());
            let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())?;
            let phrase = Zeroizing::new(mnemonic.to_string());
            println!(
                "Store these 24 recovery words securely, offline. Anyone with them can enroll administrators. They will NOT be saved or shown again. Never enter them in a browser or MCP client.\n\n{}\n",
                phrase.as_str()
            );
            confirm("Have you stored the recovery phrase securely?")?;
            enroll(&data, &phrase, name, gateway, Role::Admin).await?;
        }
        Command::Chain {
            command:
                ChainCommand::Join {
                    name,
                    gateway,
                    admin,
                    phrase_stdin,
                },
        } => {
            let _lock = lock_dir(&data)?;
            ensure!(
                !data.join("installation.json").exists(),
                "An installation already exists"
            );
            let phrase = if phrase_stdin {
                ensure!(
                    !io::stdin().is_terminal(),
                    "Use redirected stdin for --phrase-stdin"
                );
                let mut s = Zeroizing::new(String::new());
                io::stdin().take(1025).read_to_string(&mut s)?;
                ensure!(s.len() <= 1024, "Phrase input too long");
                s
            } else {
                ensure!(
                    io::stdin().is_terminal(),
                    "Use --phrase-stdin for a protected pipe"
                );
                Zeroizing::new(rpassword::prompt_password("24 recovery words (hidden): ")?)
            };
            enroll(
                &data,
                phrase.trim(),
                name,
                gateway,
                if admin { Role::Admin } else { Role::Member },
            )
            .await?;
        }
        Command::Chain {
            command: ChainCommand::Show,
        } => {
            let i = load(&data)?;
            display(
                &serde_json::json!({"chain_id":i.certificate.chain_id,"this_device":i.certificate,"gateway":i.gateway}),
            )?;
        }
        Command::Daemon => {
            let _lock = lock_dir(&data)?;
            let i = load(&data)?;
            let stop = tokio_util::sync::CancellationToken::new();
            let runner = wayfinder_agent::run(&data, &i, stop.clone());
            tokio::pin!(runner);
            tokio::select! {r=&mut runner=>r?,_=stop_signal()=>{stop.cancel();runner.await?;}}
        }
        Command::Status => show_status(&data)?,
        Command::Tui => {
            ensure!(io::stdout().is_terminal(), "TUI requires a terminal");
            loop {
                crossterm::execute!(
                    io::stdout(),
                    crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
                    crossterm::cursor::MoveTo(0, 0)
                )?;
                show_status(&data)?;
                println!(
                    "\nCtrl-C to close. Manage devices with `wayfinder devices`; MCP grants with `wayfinder auth list`."
                );
                tokio::select! {_=stop_signal()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}
            }
        }
        Command::Devices => {
            display(&wayfinder_agent::operation(&load(&data)?, Operation::Devices).await?)?
        }
        Command::Device {
            command: DeviceCommand::Revoke { id },
        } => {
            display(
                &wayfinder_agent::operation(
                    &load(&data)?,
                    Operation::RevokeDevice { device_id: id },
                )
                .await?,
            )?;
        }
        Command::Auth { command } => {
            let op = match command {
                AuthCommand::List => Operation::Grants,
                AuthCommand::Revoke { id } => Operation::RevokeGrant { grant_id: id },
            };
            display(&wayfinder_agent::operation(&load(&data)?, op).await?)?;
        }
        Command::Authorize { code } => {
            let i = load(&data)?;
            ensure!(
                i.certificate.role == Role::Admin,
                "Administrative device required"
            );
            let code = code.to_uppercase();
            let details =
                wayfinder_agent::operation(&i, Operation::Pending { code: code.clone() }).await?;
            let approval: oauth::Approval = serde_json::from_value(details.clone())?;
            println!(
                "Gateway: {}\nSync Chain: {}\nRequest (client name is self-reported):",
                i.gateway, i.certificate.chain_id
            );
            display(&details)?;
            confirm(
                "Approve these exact scopes? exec allows shell commands with each agent's OS privileges.",
            )?;
            let hash = digest(&serde_json::to_vec(&approval)?);
            display(
                &wayfinder_agent::operation(
                    &i,
                    Operation::Approve {
                        code,
                        request_hash: hash,
                    },
                )
                .await?,
            )?;
            println!("Refresh the browser authorization page to return to your MCP client.");
        }
        Command::Gateway { url } => {
            let _lock = lock_dir(&data)?;
            validate_gateway(&url)?;
            let mut i = load(&data)?;
            println!(
                "Chain: {}\nCurrent gateway: {}\nNew gateway: {}",
                i.certificate.chain_id, i.gateway, url
            );
            confirm(
                "Move this device? Revocations and MCP grants are gateway-local; a fresh gateway has neither.",
            )?;
            i.gateway = url;
            wayfinder_agent::register(&i).await?;
            atomic_write(&data.join("installation.json"), &i)?;
            println!("Gateway changed. Restart the agent.");
        }
    }
    Ok(())
}
async fn enroll(
    data: &std::path::Path,
    phrase: &str,
    name: String,
    gateway: String,
    role: Role,
) -> Result<()> {
    let root = root(phrase)?;
    let key = new_key();
    let cert = Certificate::issue(&root, &key, name, role)?;
    drop(root);
    let i = Installation::new(gateway, cert, &key)?;
    atomic_write(&data.join("installation.json"), &i)?;
    println!(
        "Sync Chain: {}\nDevice: {}",
        i.certificate.chain_id, i.certificate.device_id
    );
    wayfinder_agent::register(&i).await.context("Identity saved; gateway registration failed. Run wayfinder daemon to reconnect with this same identity")?;
    println!("Registered. Start `wayfinder daemon` or install the agent service.");
    Ok(())
}
fn show_status(data: &std::path::Path) -> Result<()> {
    let i = load(data)?;
    let mut s: serde_json::Value = read_private(&data.join("status.json"))
        .unwrap_or_else(|_| serde_json::json!({"online":false}));
    if s["observed"]
        .as_u64()
        .is_none_or(|t| now().saturating_sub(t) > 30)
    {
        s["online"] = serde_json::json!(false);
    }
    s["chain_id"] = serde_json::json!(i.certificate.chain_id);
    s["device_id"] = serde_json::json!(i.certificate.device_id);
    s["gateway"] = serde_json::json!(i.gateway);
    display(&s)
}
async fn stop_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
