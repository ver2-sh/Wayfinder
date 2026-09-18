use crate::{AuthCommand, ChainCommand, Command, DeviceCommand, GatewayCommand, service, update};
use anyhow::{Context, Result, ensure};
use std::io::{self, IsTerminal, Read, Write};
use wayfinder_core::{identity::*, protocol::Operation, *};
use zeroize::Zeroizing;
pub fn load(data: &std::path::Path) -> Result<Installation> {
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
pub fn confirm(prompt: &str) -> Result<()> {
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
pub async fn execute(data: &std::path::Path, command: Command) -> Result<()> {
    match command {
        Command::Chain {
            command: ChainCommand::Create { name, gateway },
        } => {
            let _lock = lock_dir(data)?;
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
            enroll(data, &phrase, name, gateway, Role::Admin).await?;
            enrollment_notice(data)?;
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
            let _lock = lock_dir(data)?;
            ensure!(
                !data.join("installation.json").exists(),
                "An installation already exists"
            );
            let phrase = read_phrase(phrase_stdin)?;
            enroll(
                data,
                phrase.trim(),
                name,
                gateway,
                if admin { Role::Admin } else { Role::Member },
            )
            .await?;
            enrollment_notice(data)?;
        }
        Command::Chain {
            command: ChainCommand::Show,
        } => {
            let i = load(data)?;
            display(
                &serde_json::json!({"chain_id":i.certificate.chain_id,"this_device":i.certificate,"gateway":i.gateway}),
            )?;
        }
        Command::Daemon => {
            let _lock = lock_dir(data)?;
            let i = load(data)?;
            let stop = tokio_util::sync::CancellationToken::new();
            let runner = wayfinder_agent::run(data, &i, stop.clone());
            tokio::pin!(runner);
            tokio::select! {r=&mut runner=>r?,_=stop_signal()=>{stop.cancel();runner.await?;}}
        }
        Command::Status => show_status(data)?,
        Command::Tui => anyhow::bail!("TUI must run from the interactive entry point"),
        Command::Service { command } => service::manage(data, command)?,
        Command::Update { check } => {
            let state = update::check(data, true).await?;
            println!("{}", state.message());
            if !check && state.available() {
                update::ensure_owned()?;
                confirm("Install this update? Running commands may be interrupted.")?;
                update::install(data).await?;
            }
        }
        Command::Gateway {
            command:
                GatewayCommand::Migrate {
                    gateway,
                    phrase_stdin,
                },
        } => {
            let _lock =
                lock_dir(data).context("Stop the independently running agent before migration")?;
            validate_gateway(&gateway)?;
            let i = load(data)?;
            let phrase = read_phrase(phrase_stdin)?;
            migrate(data, i, gateway, phrase.trim()).await?;
            println!("This device migrated. Authorize MCP separately at the destination.");
        }
        Command::Devices => {
            display(&wayfinder_agent::operation(&load(data)?, Operation::Devices).await?)?
        }
        Command::Device {
            command: DeviceCommand::Revoke { id, yes },
        } => {
            if !yes {
                confirm(&format!("Permanently revoke device {id}?"))?;
            }
            display(
                &wayfinder_agent::operation(
                    &load(data)?,
                    Operation::RevokeDevice { device_id: id },
                )
                .await?,
            )?;
        }
        Command::Auth { command } => {
            let op = match command {
                AuthCommand::List => Operation::Grants,
                AuthCommand::Revoke { id, yes } => {
                    if !yes {
                        confirm(&format!("Revoke MCP grant {id}?"))?;
                    }
                    Operation::RevokeGrant { grant_id: id }
                }
            };
            display(&wayfinder_agent::operation(&load(data)?, op).await?)?;
        }
        Command::Authorize { code } => {
            let i = load(data)?;
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
    }
    Ok(())
}
fn enrollment_notice(data: &std::path::Path) -> Result<()> {
    let i = load(data)?;
    println!(
        "Sync Chain: {}\nDevice: {}\nRegistered. Start `wayfinder daemon` or install the agent service.",
        i.certificate.chain_id, i.certificate.device_id
    );
    Ok(())
}
pub(crate) async fn enroll(
    data: &std::path::Path,
    phrase: &str,
    name: String,
    gateway: String,
    role: Role,
) -> Result<()> {
    let root = root(phrase)?;
    let key = new_key();
    let cert = Certificate::issue(&root, &key, name, role)?;
    let i = Installation::new(gateway, cert, &key)?;
    wayfinder_agent::admit(&i, &root).await?;
    drop(root);
    atomic_write(&data.join("installation.json"), &i)?;
    wayfinder_agent::register(&i).await.context("Identity saved; gateway registration failed. Run wayfinder daemon to reconnect with this same identity")?;
    Ok(())
}
pub fn show_status(data: &std::path::Path) -> Result<()> {
    display(&status(data)?)
}
pub fn status(data: &std::path::Path) -> Result<serde_json::Value> {
    let i = load(data)?;
    let mut s: serde_json::Value = read_private(&data.join("status.json"))
        .unwrap_or_else(|_| serde_json::json!({"online":false}));
    if !s.is_object() {
        s = serde_json::json!({"online":false});
    }
    if s["observed"]
        .as_u64()
        .is_none_or(|t| now().saturating_sub(t) > 30)
    {
        s["online"] = serde_json::json!(false);
    }
    s["chain_id"] = serde_json::json!(i.certificate.chain_id);
    s["device_id"] = serde_json::json!(i.certificate.device_id);
    s["gateway"] = serde_json::json!(i.gateway);
    s["version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    s["role"] = serde_json::json!(i.certificate.role);
    s["name"] = serde_json::json!(i.certificate.name);
    s["service_installed"] = serde_json::json!(service::installed(data)?);
    s["agent_running"] = serde_json::json!(service::agent_running(data)?);
    if s["agent_running"] == false {
        s["online"] = serde_json::json!(false);
    }
    Ok(s)
}
pub async fn stop_signal() {
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

fn read_phrase(phrase_stdin: bool) -> Result<Zeroizing<String>> {
    Ok(if phrase_stdin {
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
    })
}

/// Caller holds the installation lock for the whole transaction.
pub(crate) async fn migrate(
    data: &std::path::Path,
    i: Installation,
    gateway: String,
    phrase: &str,
) -> Result<()> {
    validate_gateway(&gateway)?;
    ensure!(
        gateway != i.gateway,
        "This device already uses that gateway"
    );
    let root = root(phrase)?;
    ensure!(
        root.verifying_key().to_bytes() == key_bytes(&i.certificate.root_public)?,
        "Recovery phrase does not match this installation root"
    );
    let target = Installation::new(gateway, i.certificate.clone(), &i.key()?)?;
    wayfinder_agent::admit(&target, &root).await.context(
        "Target admission denied; an existing revocation tombstone cannot be overridden",
    )?;
    drop(root);
    wayfinder_agent::register(&target)
        .await
        .context("Target registration failed; local gateway unchanged")?;
    atomic_write(&data.join("installation.json"), &target)?;
    Ok(())
}
