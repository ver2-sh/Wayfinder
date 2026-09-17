use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    io::{self, IsTerminal},
    path::PathBuf,
};
use wayfinder_core::{default_data_dir, identity::DEFAULT_GATEWAY};
mod app;
mod service;
mod tui;
mod update;
#[derive(Parser)]
#[command(
    version,
    about = "Accountless Sync Chain agent: outbound shell access through your gateway"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
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
    /// Interactive management of this device and chain.
    Tui,
    Update {
        #[arg(long)]
        check: bool,
    },
    Service {
        #[command(subcommand)]
        command: service::Action,
    },
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
    Revoke {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}
#[derive(Subcommand)]
enum AuthCommand {
    List,
    Revoke {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Wayfinder: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let c = Cli::parse();
    let data = c.data_dir.map(Ok).unwrap_or_else(default_data_dir)?;
    let command = c.command.unwrap_or(Command::Tui);
    if matches!(command, Command::Tui) {
        ensure!(
            io::stdin().is_terminal() && io::stdout().is_terminal(),
            "No interactive terminal. Supply a command; see wayfinder --help"
        );
        tui::run(&data).await
    } else {
        app::execute(&data, command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_and_headless_cli_parse() {
        for args in [
            vec!["wayfinder"],
            vec!["wayfinder", "tui"],
            vec!["wayfinder", "update", "--check"],
            vec!["wayfinder", "service", "install"],
            vec!["wayfinder", "device", "revoke", "id", "--yes"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        assert_eq!(
            Cli::try_parse_from(["wayfinder", "--version"])
                .err()
                .unwrap()
                .kind(),
            clap::error::ErrorKind::DisplayVersion
        );
    }
}
