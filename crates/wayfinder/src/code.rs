use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;
use wayfinder_core::code::{CodeAction, CodeInput};

#[derive(Subcommand)]
pub enum Action {
    /// Inspect configuration, runtime versions and recently observed sessions.
    Status,
    /// Prepare the private runtime now (otherwise the first code request does this).
    Prepare {
        #[arg(long, default_value_t = 300000)]
        timeout: u64,
    },
    /// Check/install a compatible code runtime without updating Wayfinder itself.
    Update {
        /// Check the release channel without downloading or activating a runtime.
        #[arg(long)]
        check: bool,
    },
    /// Enable or disable automatic code-runtime updates (true or false).
    AutoUpdates {
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Select the previous installed runtime for future sessions; never replay an edit.
    Rollback,
    /// Enable on-demand code intelligence without installing or starting anything now.
    Enable,
    /// Disable code intelligence and cancel its sessions without stopping Wayfinder.
    Disable,
    /// Remove downloaded runtime/cache data; project memories and identity are retained.
    Clean {
        #[arg(long)]
        yes: bool,
    },
    /// Show bundled dependency license and source notices.
    Licenses,
}
pub async fn prepare(data: &Path, timeout: u64) -> Result<serde_json::Value> {
    let manager = wayfinder_code::Manager::new(data);
    let input = CodeInput {
        target: "local".into(),
        action: CodeAction::Prepare,
        project: None,
        tool: None,
        arguments: None,
        timeout: Some(timeout),
    };
    let cancel = CancellationToken::new();
    let result = tokio::select! {
        result = manager.execute(input.clone(), cancel.clone()) => result,
        _ = crate::app::stop_signal() => { cancel.cancel(); wayfinder_core::code::CodeResult::failed(&input, "Code runtime preparation cancelled") }
    };
    manager.shutdown().await;
    ensure!(
        !result.is_error(),
        "{}",
        result
            .error
            .unwrap_or_else(|| "Code runtime preparation failed".into())
    );
    Ok(result.result.unwrap_or_default())
}
pub async fn execute(data: &Path, action: Action) -> Result<()> {
    match action {
        Action::Status => println!(
            "{}",
            serde_json::to_string_pretty(&wayfinder_code::local_status(data)?)?
        ),
        Action::Prepare { timeout } => println!(
            "{}",
            serde_json::to_string_pretty(&prepare(data, timeout).await?)?
        ),
        Action::Update { check } => {
            let status = tokio::select! {
                _ = crate::app::stop_signal() => anyhow::bail!("Code runtime update cancelled; no user operation was replayed"),
                result = tokio::time::timeout(Duration::from_secs(270), wayfinder_code::updates::update(data, check)) => result.context("Code runtime update timed out")??,
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
            ensure!(
                status["last_error"].is_null(),
                "Code runtime update was not completed; see the reported update status"
            );
        }
        Action::AutoUpdates { enabled } => {
            wayfinder_code::Settings::set_automatic_updates(data, enabled)?;
            println!(
                "Automatic code runtime updates {}. Wayfinder application updates are unchanged.",
                if enabled { "enabled" } else { "disabled" }
            );
        }
        Action::Rollback => {
            let status = wayfinder_code::updates::rollback(data).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Action::Enable | Action::Disable => {
            let enabled = matches!(action, Action::Enable);
            wayfinder_code::Settings::set_enabled(data, enabled)?;
            println!(
                "{}",
                if enabled {
                    "Code intelligence enabled. The runtime is prepared on first use."
                } else {
                    "Code intelligence disabled. Active code sessions are being cancelled; files and project memories are retained."
                }
            );
        }
        Action::Clean { yes } => {
            if !yes {
                crate::app::confirm(
                    "Remove the private code runtime and download cache? Project memories and Wayfinder identity are retained.",
                )?;
            }
            wayfinder_code::clean(data)?;
            println!(
                "Code runtime/cache removed. Project memories and Wayfinder identity retained."
            );
        }
        Action::Licenses => print!("{}", include_str!("../../wayfinder-code/NOTICE.md")),
    }
    Ok(())
}
