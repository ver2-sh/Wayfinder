//! Per-user native startup. No elevation, shell interpolation, or privileged accounts.
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use wayfinder_core::{lock_dir, private_dir};

#[derive(Clone, Copy, Subcommand)]
pub enum Action {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

pub fn agent_running(data: &Path) -> Result<bool> {
    // Distinguish contention from permissions/corrupt paths instead of treating all errors as running.
    private_dir(data)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(data.join("daemon.lock"))?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(false),
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn id(data: &Path) -> Result<String> {
    private_dir(data)?;
    Ok(format!(
        "app.usewayfinder.agent.{}",
        &wayfinder_core::digest(std::fs::canonicalize(data)?.to_string_lossy().as_bytes())[..16]
    ))
}
#[cfg(target_os = "macos")]
fn home() -> Result<PathBuf> {
    Ok(directories::BaseDirs::new()
        .context("No user home directory")?
        .home_dir()
        .to_owned())
}
fn invoke(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run {program}; is this user session supported?"))?;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
#[cfg(target_os = "linux")]
fn definition(data: &Path) -> Result<PathBuf> {
    Ok(directories::BaseDirs::new()
        .context("No user config directory")?
        .config_dir()
        .join("systemd/user")
        .join(format!("{}.service", id(data)?)))
}
#[cfg(target_os = "macos")]
fn definition(data: &Path) -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", id(data)?)))
}
#[cfg(windows)]
fn definition(data: &Path) -> Result<PathBuf> {
    Ok(data.join("startup-task.json"))
}
pub fn installed(data: &Path) -> Result<bool> {
    Ok(definition(data)?.exists())
}

pub fn manage(data: &Path, action: Action) -> Result<()> {
    if matches!(action, Action::Status) {
        println!(
            "Startup definition installed: {}\nAgent running: {}",
            installed(data)?,
            agent_running(data)?
        );
        return Ok(());
    }
    if matches!(action, Action::Install | Action::Start | Action::Restart) {
        crate::app::load(data)?;
    }
    if matches!(action, Action::Install) {
        ensure!(
            !agent_running(data)?,
            "Stop the existing agent before configuring startup"
        );
    }
    native(data, action)?;
    println!("Service operation completed for the current OS user.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn native(data: &Path, action: Action) -> Result<()> {
    let file = definition(data)?;
    let unit = format!("{}.service", id(data)?);
    match action {
        Action::Install => {
            // systemd specifier/environment expansion applies even inside quotes.
            fn quote(p: &Path) -> Result<String> {
                let s = p.to_str().context("Service paths must be UTF-8")?;
                ensure!(
                    !s.chars().any(char::is_control),
                    "Control characters in service path"
                );
                Ok(format!(
                    "\"{}\"",
                    s.replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('%', "%%")
                        .replace('$', "$$")
                ))
            }
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(
                &file,
                format!(
                    "[Unit]\nDescription=Wayfinder agent (current user)\n[Service]\nExecStart={} --data-dir {} daemon\nRestart=on-failure\nRestartSec=5\nUMask=0077\n[Install]\nWantedBy=default.target\n",
                    quote(&std::env::current_exe()?)?,
                    quote(&std::fs::canonicalize(data)?)?
                ),
            )?;
            invoke("systemctl", &["--user", "daemon-reload"])?;
            invoke("systemctl", &["--user", "enable", "--now", &unit])?;
        }
        Action::Uninstall => {
            invoke("systemctl", &["--user", "disable", "--now", &unit])?;
            std::fs::remove_file(file)?;
            invoke("systemctl", &["--user", "daemon-reload"])?;
        }
        Action::Start | Action::Stop | Action::Restart => {
            ensure!(file.exists(), "Install automatic startup first");
            let verb = match action {
                Action::Start => "start",
                Action::Stop => "stop",
                _ => "restart",
            };
            invoke("systemctl", &["--user", verb, &unit])?;
        }
        Action::Status => unreachable!(),
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn native(data: &Path, action: Action) -> Result<()> {
    fn xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    let file = definition(data)?;
    let uid = invoke("id", &["-u"])?;
    let domain = format!("gui/{}", uid.trim());
    let label = id(data)?;
    let target = format!("{domain}/{label}");
    let path = file.to_str().context("LaunchAgent path must be UTF-8")?;
    match action {
        Action::Install => {
            std::fs::create_dir_all(file.parent().unwrap())?;
            let exe = std::env::current_exe()?;
            let data = std::fs::canonicalize(data)?;
            std::fs::write(
                &file,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{}</string><string>--data-dir</string><string>{}</string><string>daemon</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>Umask</key><integer>63</integer></dict></plist>",
                    xml(exe.to_str().context("Executable path must be UTF-8")?),
                    xml(data.to_str().context("Data path must be UTF-8")?)
                ),
            )?;
            invoke("launchctl", &["bootstrap", &domain, path])?;
        }
        Action::Start => {
            invoke("launchctl", &["bootstrap", &domain, path])?;
        }
        Action::Stop => {
            invoke("launchctl", &["bootout", &target])?;
        }
        Action::Restart => {
            invoke("launchctl", &["kickstart", "-k", &target])?;
        }
        Action::Uninstall => {
            if invoke("launchctl", &["print", &target]).is_ok() {
                invoke("launchctl", &["bootout", &target])?;
            }
            std::fs::remove_file(file)?;
        }
        Action::Status => unreachable!(),
    }
    Ok(())
}
#[cfg(windows)]
fn native(data: &Path, action: Action) -> Result<()> {
    fn ps(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }
    let name = ps(&id(data)?);
    let script = match action {
        Action::Install => {
            let exe = std::env::current_exe()?;
            let data = std::fs::canonicalize(data)?;
            let data = data.to_str().context("Data path must be UTF-8")?;
            ensure!(!data.contains('"'), "Invalid data path");
            format!(
                "$a=New-ScheduledTaskAction -Execute {} -Argument {}; $u=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; $t=New-ScheduledTaskTrigger -AtLogOn -User $u; $s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName {name} -Action $a -Principal $p -Trigger $t -Settings $s -Force | Out-Null; Start-ScheduledTask -TaskName {name}",
                ps(exe.to_str().context("Executable path must be UTF-8")?),
                ps(&format!("--data-dir \"{data}\" daemon"))
            )
        }
        Action::Start => format!("Start-ScheduledTask -TaskName {name}"),
        Action::Stop => format!("Stop-ScheduledTask -TaskName {name}"),
        Action::Restart => {
            format!("Stop-ScheduledTask -TaskName {name}; Start-ScheduledTask -TaskName {name}")
        }
        Action::Uninstall => format!(
            "Stop-ScheduledTask -TaskName {name}; Unregister-ScheduledTask -TaskName {name} -Confirm:$false"
        ),
        Action::Status => unreachable!(),
    };
    invoke(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference='Stop'; {script}"),
        ],
    )?;
    if matches!(action, Action::Install) {
        wayfinder_core::atomic_write(&definition(data)?, &true)?;
    }
    if matches!(action, Action::Uninstall) {
        std::fs::remove_file(definition(data)?)?;
    }
    Ok(())
}

pub async fn wait_stopped(data: &Path) -> Result<()> {
    for _ in 0..100 {
        if !agent_running(data)? {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!(
        "Agent still owns the data directory; stop the independently launched daemon first"
    )
}

pub struct TemporaryAgent {
    stop: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl TemporaryAgent {
    pub fn start(data: &Path) -> Result<Self> {
        let lock = lock_dir(data)?;
        let installation = crate::app::load(data)?;
        let stop = tokio_util::sync::CancellationToken::new();
        let token = stop.clone();
        let data = data.to_owned();
        let task = tokio::spawn(async move {
            let _lock = lock;
            wayfinder_agent::run(&data, &installation, token).await
        });
        Ok(Self { stop, task })
    }
    pub async fn stop(self) -> Result<()> {
        self.stop.cancel();
        self.task.await??;
        Ok(())
    }
}
