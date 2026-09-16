//! A deliberately small, line-oriented terminal UI. Cooked input keeps hidden recovery
//! prompts compatible with the CLI; no readline history ever records secrets.
use crate::{
    AuthCommand, ChainCommand, Command, DeviceCommand, app,
    service::{self, Action, TemporaryAgent},
    update,
};
use anyhow::{Result, ensure};
use std::{
    io::{self, Write},
    path::Path,
};
use wayfinder_core::identity::DEFAULT_GATEWAY;
fn input(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut s = String::new();
    ensure!(io::stdin().read_line(&mut s)? > 0, "Terminal input closed");
    Ok(s.trim().to_owned())
}
fn gateway() -> Result<String> {
    let s = input(&format!("Gateway [Enter for {DEFAULT_GATEWAY}]"))?;
    Ok(if s.is_empty() {
        DEFAULT_GATEWAY.into()
    } else {
        s
    })
}
fn clear() -> Result<()> {
    crossterm::execute!(
        io::stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::Purge),
        crossterm::cursor::MoveTo(0, 0)
    )?;
    Ok(())
}
pub async fn run(data: &Path) -> Result<()> {
    let mut owned = None;
    let cache_data = data.to_owned();
    let check = tokio::spawn(async move { update::check(&cache_data, false).await });
    let result = session(data, &mut owned, check).await;
    if let Some(agent) = owned {
        agent.stop().await?;
    }
    clear()?;
    result
}
async fn session(
    data: &Path,
    owned: &mut Option<TemporaryAgent>,
    mut check: tokio::task::JoinHandle<Result<update::State>>,
) -> Result<()> {
    let mut update_message = "Update check in background…".to_owned();
    let mut checked = false;
    loop {
        clear()?;
        println!("WAYFINDER {}\n", update::CURRENT);
        if let Err(e) = app::show_status(data) {
            println!("Not enrolled or identity unavailable: {e}");
        }
        if !checked && check.is_finished() {
            update_message = match (&mut check).await {
                Ok(Ok(s)) => s.message(),
                _ => "Update check unavailable; agent operation unaffected".into(),
            };
            checked = true;
        }
        println!(
            "\n{update_message}\n\n1 Create Chain   2 Join Chain   3 Devices   4 Revoke device\n5 MCP grants     6 Revoke grant 7 Approve pairing code\n8 Change gateway 9 Agent        u Updates  r Refresh  q Quit\n\nUse a private, unrecorded terminal. Remote commands run as your OS user."
        );
        let choice = menu_key().await?;
        if choice == "q" {
            break;
        }
        let result = action(data, owned, &choice).await;
        if let Err(e) = result {
            println!("Action failed: {e:#}");
        }
        if choice != "r" {
            input("Enter to return")?;
        }
    }
    check.abort();
    Ok(())
}
async fn stop_owned(owned: &mut Option<TemporaryAgent>) -> Result<bool> {
    if let Some(agent) = owned.take() {
        agent.stop().await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
async fn action(data: &Path, owned: &mut Option<TemporaryAgent>, choice: &str) -> Result<()> {
    let command = match choice {
        "1" => Command::Chain {
            command: ChainCommand::Create {
                name: input("Device name")?,
                gateway: gateway()?,
            },
        },
        "2" => {
            let name = input("Device name")?;
            let gateway = gateway()?;
            let admin = input("Role: member [Enter] or admin")?;
            ensure!(
                admin.is_empty() || admin == "member" || admin == "admin",
                "Choose member or admin"
            );
            Command::Chain {
                command: ChainCommand::Join {
                    name,
                    gateway,
                    admin: admin == "admin",
                    phrase_stdin: false,
                },
            }
        }
        "3" => Command::Devices,
        "4" => Command::Device {
            command: DeviceCommand::Revoke {
                id: input("Device ID to revoke permanently")?,
                yes: false,
            },
        },
        "5" => Command::Auth {
            command: AuthCommand::List,
        },
        "6" => Command::Auth {
            command: AuthCommand::Revoke {
                id: input("Grant ID to revoke")?,
                yes: false,
            },
        },
        "7" => Command::Authorize {
            code: input("Pairing code from your browser")?,
        },
        "8" => {
            let url = gateway()?;
            wayfinder_core::identity::validate_gateway(&url)?;
            if owned.is_some() {
                app::confirm(
                    "Stop the temporary agent to change gateway? Active commands may be interrupted.",
                )?;
            }
            let was_owned = stop_owned(owned).await?;
            let result = app::execute(data, Command::Gateway { url }).await;
            if was_owned {
                *owned = Some(TemporaryAgent::start(data)?);
            }
            return result;
        }
        "9" => {
            service::manage(data, Action::Status)?;
            println!(
                "start = temporary agent (stops on TUI exit); install = automatic startup\nstop / restart = control agent; uninstall = disable automatic startup"
            );
            match input("Agent action")?.as_str() {
                "start" => {
                    ensure!(
                        !service::agent_running(data)?,
                        "An agent already owns this directory"
                    );
                    if service::installed(data)? {
                        service::manage(data, Action::Start)?;
                    } else {
                        *owned = Some(TemporaryAgent::start(data)?);
                    }
                }
                "stop" => {
                    if !stop_owned(owned).await? {
                        service::manage(data, Action::Stop)?;
                    }
                }
                "restart" => {
                    if stop_owned(owned).await? {
                        *owned = Some(TemporaryAgent::start(data)?);
                    } else {
                        service::manage(data, Action::Restart)?;
                    }
                }
                "install" => {
                    app::confirm("Enable automatic startup as this OS user?")?;
                    stop_owned(owned).await?;
                    service::manage(data, Action::Install)?;
                }
                "uninstall" => {
                    app::confirm("Disable automatic startup and stop the managed agent?")?;
                    service::manage(data, Action::Uninstall)?;
                }
                _ => anyhow::bail!("Unknown agent action"),
            }
            return Ok(());
        }
        "u" => {
            let state = update::check(data, true).await?;
            println!("{}", state.message());
            if state.available() {
                update::ensure_owned()?;
                app::confirm(
                    "Install the update? Active commands may be interrupted; reopen the TUI afterward.",
                )?;
                let was_owned = stop_owned(owned).await?;
                let result = update::install(data).await;
                if was_owned && result.is_err() {
                    *owned = Some(TemporaryAgent::start(data)?);
                }
                result?;
            }
            return Ok(());
        }
        "r" => return Ok(()),
        _ => anyhow::bail!("Choose an item from the menu"),
    };
    app::execute(data, command).await
}

async fn menu_key() -> Result<String> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        terminal,
    };
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = terminal::disable_raw_mode();
        }
    }
    terminal::enable_raw_mode()?;
    let _restore = Restore;
    let refresh = std::time::Instant::now();
    loop {
        if refresh.elapsed() >= std::time::Duration::from_secs(2) {
            return Ok("r".into());
        }
        if event::poll(std::time::Duration::ZERO)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok("q".into());
                }
                KeyCode::Char(c) => return Ok(c.to_string()),
                KeyCode::Esc => return Ok("q".into()),
                _ => {}
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
