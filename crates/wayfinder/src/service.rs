//! Per-user native startup. No elevation, shell interpolation, or privileged accounts.
//!
//! Two distinct primitives exist on purpose:
//! - `configure` changes only whether the agent starts at the NEXT login. It
//!   never starts, stops, or restarts a currently running agent.
//! - `manage`/`manage_quiet` are the lifecycle commands (`service install`,
//!   `start`, `stop`, `restart`, `uninstall`) and keep their documented
//!   process-affecting behavior for scripts and automation.
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;
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

/// Registration-only change: controls whether the agent launches at the next
/// login. Never affects a currently running agent.
#[derive(Clone, Copy)]
pub enum Configure {
    Enable,
    Disable,
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
    #[cfg(all(test, unix))]
    if program == "systemctl" {
        return test_systemctl(args);
    }
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

// Synthetic user-unit manager used by tests so enable/disable round-trips can be
// validated without a real systemd --user session.
#[cfg(all(test, unix))]
fn test_systemctl(args: &[&str]) -> Result<String> {
    let dir = test_units_dir().context("test units dir unset")?;
    let unit = args.last().unwrap_or(&"");
    let link = dir.join("default.target.wants").join(unit);
    match args.get(1).copied().unwrap_or("") {
        "daemon-reload" => Ok(String::new()),
        "enable" => {
            ensure!(dir.join(unit).is_file(), "Unit file {unit} does not exist");
            std::fs::create_dir_all(link.parent().unwrap())?;
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(dir.join(unit), &link)?;
            Ok(String::new())
        }
        "disable" => {
            ensure!(dir.join(unit).is_file(), "Unit file {unit} does not exist");
            let _ = std::fs::remove_file(&link);
            Ok(String::new())
        }
        "start" | "stop" | "restart" => Ok(String::new()),
        "is-enabled" => Ok(if link.symlink_metadata().is_ok() {
            "enabled".into()
        } else {
            "disabled".into()
        }),
        "is-active" => Ok("inactive".into()),
        verb => anyhow::bail!("unexpected systemctl verb {verb}"),
    }
}
#[cfg(all(test, unix))]
fn test_units_dir() -> Option<PathBuf> {
    TEST_UNITS_DIR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}
#[cfg(all(test, unix))]
pub(crate) fn test_set_units_dir(dir: &Path) {
    *TEST_UNITS_DIR.lock().unwrap() = Some(dir.to_owned());
}
#[cfg(all(test, unix))]
static TEST_UNITS_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
/// Serializes tests that mutate the shared test units dir/systemctl shim.
#[cfg(all(test, unix))]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
#[cfg(all(test, unix))]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
fn units_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = test_units_dir() {
        return Ok(dir);
    }
    Ok(directories::BaseDirs::new()
        .context("No user config directory")?
        .config_dir()
        .join("systemd/user"))
}
#[cfg(target_os = "linux")]
fn definition(data: &Path) -> Result<PathBuf> {
    Ok(units_dir()?.join(format!("{}.service", id(data)?)))
}
// The enablement symlink `systemctl --user enable` creates. Checking it keeps
// `installed` truthful when the unit is disabled externally.
#[cfg(target_os = "linux")]
fn wants_link(data: &Path) -> Result<PathBuf> {
    Ok(units_dir()?
        .join("default.target.wants")
        .join(format!("{}.service", id(data)?)))
}
#[cfg(target_os = "macos")]
fn definition(data: &Path) -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", id(data)?)))
}
/// Whether the OS registration that launches the agent at next login exists and
/// is healthy. The native definition is authoritative; no marker or
/// desired-state flag is consulted, so external removal or disabling is
/// reported truthfully.
#[cfg(target_os = "linux")]
pub fn installed(data: &Path) -> Result<bool> {
    Ok(definition(data)?.exists() && wants_link(data)?.symlink_metadata().is_ok())
}
#[cfg(target_os = "macos")]
pub fn installed(data: &Path) -> Result<bool> {
    Ok(definition(data)?.exists())
}
#[cfg(windows)]
pub fn installed(data: &Path) -> Result<bool> {
    windows_installed(data)
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn installed(_data: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
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
    manage_quiet(data, action)?;
    println!("Service operation completed for the current OS user.");
    Ok(())
}

pub fn manage_quiet(data: &Path, action: Action) -> Result<()> {
    if matches!(action, Action::Install | Action::Start | Action::Restart) {
        crate::app::load(data)?;
    }
    if matches!(action, Action::Install) {
        ensure!(
            !agent_running(data)?,
            "Stop the existing agent before configuring startup"
        );
    }
    native(data, action)
}

/// Configure whether the agent launches at the next login for this OS user.
/// Configuration-only: unlike `manage_quiet`, this never starts, stops, or
/// restarts a running agent, so the TUI can toggle it while its temporary
/// agent keeps running.
pub fn configure(data: &Path, change: Configure) -> Result<()> {
    if matches!(change, Configure::Enable) {
        ensure!(
            data.join("installation.json").exists(),
            "Enroll this device before enabling login startup"
        );
    }
    native_configure(data, change)
}

// systemd specifier/environment expansion applies even inside quotes.
#[cfg(target_os = "linux")]
fn systemd_quote(p: &Path) -> Result<String> {
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

#[cfg(target_os = "linux")]
fn unit_text(data: &Path) -> Result<String> {
    Ok(format!(
        "[Unit]\nDescription=Wayfinder agent (current user)\n[Service]\nExecStart={} --data-dir {} daemon\nRestart=on-failure\nRestartSec=5\nUMask=0077\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&std::env::current_exe()?)?,
        systemd_quote(&std::fs::canonicalize(data)?)?
    ))
}

#[cfg(target_os = "linux")]
fn native_configure(data: &Path, change: Configure) -> Result<()> {
    let file = definition(data)?;
    let wants = wants_link(data)?;
    let unit = format!("{}.service", id(data)?);
    match change {
        Configure::Enable => {
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(&file, unit_text(data)?)?;
            invoke("systemctl", &["--user", "daemon-reload"])?;
            // `enable` without `--now` registers next-login startup only and
            // does not launch a second agent now.
            invoke("systemctl", &["--user", "enable", &unit])?;
        }
        Configure::Disable => {
            // `disable` never stops a running unit; removing the definition
            // files is what prevents the next login from starting the agent.
            if file.exists() {
                let _ = invoke("systemctl", &["--user", "disable", &unit]);
            }
            remove_if_exists(&wants)?;
            remove_if_exists(&file)?;
            if file.exists() || wants.symlink_metadata().is_ok() {
                anyhow::bail!("Startup definition could not be fully removed");
            }
            let _ = invoke("systemctl", &["--user", "daemon-reload"]);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn native(data: &Path, action: Action) -> Result<()> {
    let file = definition(data)?;
    let unit = format!("{}.service", id(data)?);
    match action {
        Action::Install => {
            native_configure(data, Configure::Enable)?;
            // Documented behavior: `service install` also starts the agent now.
            invoke("systemctl", &["--user", "start", &unit])?;
        }
        Action::Uninstall => {
            invoke("systemctl", &["--user", "stop", &unit])?;
            native_configure(data, Configure::Disable)?;
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

#[cfg(any(target_os = "macos", test))]
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(any(target_os = "macos", test))]
fn plist_text(data: &Path) -> Result<String> {
    let label = id(data)?;
    let exe = std::env::current_exe()?;
    let data = std::fs::canonicalize(data)?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{}</string><string>--data-dir</string><string>{}</string><string>daemon</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>Umask</key><integer>63</integer></dict></plist>",
        xml(exe.to_str().context("Executable path must be UTF-8")?),
        xml(data.to_str().context("Data path must be UTF-8")?)
    ))
}

#[cfg(target_os = "macos")]
fn native_configure(data: &Path, change: Configure) -> Result<()> {
    let file = definition(data)?;
    match change {
        // A LaunchAgent plist in ~/Library/LaunchAgents is loaded by launchd at
        // the next login; writing it does not start anything now.
        Configure::Enable => {
            std::fs::create_dir_all(file.parent().unwrap())?;
            std::fs::write(&file, plist_text(data)?)?;
        }
        Configure::Disable => remove_if_exists(&file)?,
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn native(data: &Path, action: Action) -> Result<()> {
    let file = definition(data)?;
    let uid = invoke("id", &["-u"])?;
    let domain = format!("gui/{}", uid.trim());
    let label = id(data)?;
    let target = format!("{domain}/{label}");
    let path = file.to_str().context("LaunchAgent path must be UTF-8")?;
    match action {
        Action::Install => {
            // Documented behavior: `service install` also starts the agent now.
            native_configure(data, Configure::Enable)?;
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
            native_configure(data, Configure::Disable)?;
        }
        Action::Status => unreachable!(),
    }
    Ok(())
}

// Encode one argv element using Windows CRT quote/backslash rules. PowerShell
// quoting is a separate outer layer; its single-quoted strings preserve this.
#[cfg(any(windows, test))]
fn windows_argument(value: &str) -> String {
    let mut encoded = String::from("\"");
    let mut backslashes = 0;
    for c in value.chars() {
        if c == '\\' {
            backslashes += 1;
            continue;
        }
        encoded.extend(std::iter::repeat_n(
            '\\',
            if c == '"' {
                backslashes * 2 + 1
            } else {
                backslashes
            },
        ));
        encoded.push(c);
        backslashes = 0;
    }
    encoded.extend(std::iter::repeat_n('\\', backslashes * 2));
    encoded.push('"');
    encoded
}

#[cfg(any(windows, test))]
fn windows_task_arguments(data: &str) -> String {
    format!("--data-dir {} daemon", windows_argument(data))
}

#[cfg(any(windows, test))]
fn windows_ps(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// One Task Scheduler trigger as reported by the query script.
#[cfg(any(windows, test))]
#[derive(Debug, serde::Deserialize)]
struct WindowsTriggerView {
    #[serde(default, rename = "type")]
    trigger_type: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// The Task Scheduler task as reported by the query script. Built from
/// structured PowerShell objects (`Get-ScheduledTask` properties), never from
/// localized human-readable `schtasks` text.
#[cfg(any(windows, test))]
#[derive(Debug, serde::Deserialize)]
struct WindowsTaskView {
    #[serde(default)]
    present: bool,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    current_user: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    logon_type: Option<String>,
    #[serde(default)]
    run_level: Option<String>,
    #[serde(default)]
    triggers: Vec<WindowsTriggerView>,
    #[serde(default)]
    execute: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

#[cfg(any(windows, test))]
fn windows_parse<T: serde::de::DeserializeOwned>(output: &str) -> Result<T> {
    serde_json::from_str(output.trim()).context("Unexpected Task Scheduler query output")
}

// Registers (or replaces) the per-user AtLogOn task without starting it.
// Current user, interactive logon, limited run level, no elevation.
#[cfg(any(windows, test))]
fn windows_register_script(name: &str, exe: &str, data: &str) -> String {
    format!(
        "$a=New-ScheduledTaskAction -Execute {} -Argument {}; $u=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; $t=New-ScheduledTaskTrigger -AtLogOn -User $u; $s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName {name} -Action $a -Principal $p -Trigger $t -Settings $s -Force | Out-Null",
        windows_ps(exe),
        windows_ps(&windows_task_arguments(data))
    )
}

// Unregisters the task only if present; never stops task instances.
#[cfg(any(windows, test))]
fn windows_unregister_script(name: &str) -> String {
    format!(
        "if (Get-ScheduledTask -TaskName {name} -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName {name} -Confirm:$false }}"
    )
}

// Emits the registered task as structured JSON, or `{"present":false}`. Reports
// the task enabled flag, current user, principal semantics, triggers, and the
// first action's executable and arguments so health is judged against the full
// login-start contract rather than mere task existence.
#[cfg(any(windows, test))]
fn windows_query_script(name: &str) -> String {
    format!(
        "$n={name}; $me=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $t=Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; if ($null -eq $t) {{ [pscustomobject]@{{ present=$false; current_user=$me }} | ConvertTo-Json -Compress }} else {{ $a=@($t.Actions); $tr=@(@($t.Triggers) | ForEach-Object {{ [pscustomobject]@{{ type=[string]$_.CimClass.CimClassName; user=$_.UserId; enabled=$_.Enabled }} }}); $exe=$null; $argstr=$null; if ($a.Count -gt 0) {{ $exe=[string]$a[0].Execute; $argstr=[string]$a[0].Arguments }}; [pscustomobject]@{{ present=$true; enabled=[bool]$t.Settings.Enabled; current_user=$me; user=[string]$t.Principal.UserId; logon_type=[string]$t.Principal.LogonType; run_level=[string]$t.Principal.RunLevel; triggers=$tr; execute=$exe; arguments=$argstr }} | ConvertTo-Json -Compress -Depth 6 }}"
    )
}

/// Judges a queried task against the exact login-start contract Wayfinder owns:
/// present, enabled, current-user interactive/limited principal, an AtLogOn
/// trigger for that user, the exact executable, and the exact
/// `--data-dir <canonical> daemon` arguments. `Enabled` is only reported when
/// Windows will actually run the expected Wayfinder login task.
#[cfg(any(windows, test))]
fn windows_task_healthy(
    view: &WindowsTaskView,
    expected_executable: &str,
    expected_arguments: &str,
) -> bool {
    if !view.present {
        return false;
    }
    let current_user = view.current_user.as_deref().unwrap_or_default();
    view.enabled
        && view.execute.as_deref() == Some(expected_executable)
        && view.arguments.as_deref() == Some(expected_arguments)
        && view
            .user
            .as_deref()
            .is_some_and(|user| user.eq_ignore_ascii_case(current_user))
        && view
            .logon_type
            .as_deref()
            .is_some_and(|logon| logon.eq_ignore_ascii_case("Interactive"))
        && view
            .run_level
            .as_deref()
            .is_some_and(|level| level.eq_ignore_ascii_case("Limited"))
        && view.triggers.iter().any(|trigger| {
            trigger
                .trigger_type
                .to_ascii_lowercase()
                .contains("logontrigger")
                && trigger
                    .user
                    .as_deref()
                    .is_some_and(|user| user.eq_ignore_ascii_case(current_user))
                && trigger.enabled.unwrap_or(true)
        })
}

#[cfg(windows)]
fn windows_run(script: &str) -> Result<()> {
    invoke(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference='Stop'; {script}"),
        ],
    )?;
    Ok(())
}

#[cfg(windows)]
fn windows_installed(data: &Path) -> Result<bool> {
    let name = id(data)?;
    let exe = std::env::current_exe()?;
    let exe = exe.to_str().context("Executable path must be UTF-8")?;
    let canonical = std::fs::canonicalize(data)?;
    let canonical = canonical.to_str().context("Data path must be UTF-8")?;
    let expected_arguments = windows_task_arguments(canonical);
    let output = invoke(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "$ErrorActionPreference='Stop'; {}",
                windows_query_script(&windows_ps(&name))
            ),
        ],
    )?;
    let view: WindowsTaskView = windows_parse(&output)?;
    Ok(windows_task_healthy(&view, exe, &expected_arguments))
}

#[cfg(windows)]
fn native_configure(data: &Path, change: Configure) -> Result<()> {
    let name = windows_ps(&id(data)?);
    match change {
        Configure::Enable => {
            let exe = std::env::current_exe()?;
            let data = std::fs::canonicalize(data)?;
            let data = data.to_str().context("Data path must be UTF-8")?;
            ensure!(!data.contains('"'), "Invalid data path");
            windows_run(&windows_register_script(
                &name,
                exe.to_str().context("Executable path must be UTF-8")?,
                data,
            ))?;
        }
        Configure::Disable => {
            windows_run(&windows_unregister_script(&name))?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn native(data: &Path, action: Action) -> Result<()> {
    let name = windows_ps(&id(data)?);
    match action {
        Action::Install => {
            native_configure(data, Configure::Enable)?;
            // Documented behavior: `service install` also starts the agent now.
            windows_run(&format!("Start-ScheduledTask -TaskName {name}"))?;
        }
        Action::Start => windows_run(&format!("Start-ScheduledTask -TaskName {name}"))?,
        Action::Stop => windows_run(&format!("Stop-ScheduledTask -TaskName {name}"))?,
        Action::Restart => windows_run(&format!(
            "Stop-ScheduledTask -TaskName {name}; Start-ScheduledTask -TaskName {name}"
        ))?,
        Action::Uninstall => {
            windows_run(&format!(
                "Stop-ScheduledTask -TaskName {name}; Unregister-ScheduledTask -TaskName {name} -Confirm:$false"
            ))?;
        }
        Action::Status => unreachable!(),
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
    task: Option<tokio::task::JoinHandle<Result<()>>>,
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
            wayfinder_agent::run_quiet(&data, &installation, token).await
        });
        Ok(Self {
            stop,
            task: Some(task),
        })
    }
    pub async fn stop(mut self) -> Result<()> {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn stub() -> Self {
        Self {
            stop: tokio_util::sync::CancellationToken::new(),
            task: None,
        }
    }
    #[cfg(test)]
    pub(crate) fn stop_requested(&self) -> bool {
        self.stop.is_cancelled()
    }
}

impl Drop for TemporaryAgent {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_task_command_lines() {
        for (path, command) in [
            (r"C:\wayfinder", r#"--data-dir "C:\wayfinder" daemon"#),
            (
                r"C:\My Data\wayfinder",
                r#"--data-dir "C:\My Data\wayfinder" daemon"#,
            ),
            (r"C:\My Data\", r#"--data-dir "C:\My Data\\" daemon"#),
            (r"C:\", r#"--data-dir "C:\\" daemon"#),
            (
                r"\\?\C:\My Data\",
                r#"--data-dir "\\?\C:\My Data\\" daemon"#,
            ),
        ] {
            assert_eq!(windows_task_arguments(path), command);
        }
        assert_eq!(windows_argument(""), r#""""#);
        assert_eq!(windows_argument(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn windows_powershell_single_quote_escapes() {
        assert_eq!(windows_ps("plain"), "'plain'");
        assert_eq!(
            windows_ps(r"C:\My Apps\wayfinder.exe"),
            r"'C:\My Apps\wayfinder.exe'"
        );
        // Trailing backslashes are literal inside PowerShell single quotes.
        assert_eq!(windows_ps(r"C:\Tools\"), r"'C:\Tools\'");
        assert_eq!(windows_ps("it's"), "'it''s'");
    }

    #[test]
    fn windows_register_script_is_registration_only_and_safely_quoted() {
        let script = windows_register_script(
            &windows_ps("app.usewayfinder.agent.0123456789abcdef"),
            r"C:\My Apps\wayfinder.exe",
            r"C:\My Data\wayfinder\",
        );
        // Never starts the task: configuration-only registration.
        assert!(!script.contains("Start-ScheduledTask"));
        assert!(script.contains("Register-ScheduledTask"));
        assert!(script.contains("-AtLogOn"));
        assert!(script.contains("-LogonType Interactive -RunLevel Limited"));
        assert!(script.contains("ExecutionTimeLimit ([TimeSpan]::Zero)"));
        assert!(script.contains(r"-Execute 'C:\My Apps\wayfinder.exe'"));
        assert!(script.contains(r#"--data-dir "C:\My Data\wayfinder\\" daemon"#));
    }

    fn healthy_windows_task(exe: &str, args: &str) -> WindowsTaskView {
        let json = serde_json::json!({
            "present": true,
            "enabled": true,
            "current_user": r"DESKTOP\alice",
            "user": r"DESKTOP\alice",
            "logon_type": "Interactive",
            "run_level": "Limited",
            "triggers": [
                {"type": "MSFT_TaskLogonTrigger", "user": r"DESKTOP\alice", "enabled": true}
            ],
            "execute": exe,
            "arguments": args,
        });
        windows_parse(&json.to_string()).unwrap()
    }

    #[test]
    fn windows_task_health_requires_full_login_contract() {
        let exe = r"C:\Apps\wayfinder.exe";
        let args = windows_task_arguments(r"C:\My Data\wayfinder");

        // Absent task: not healthy.
        let absent: WindowsTaskView =
            windows_parse(r#"{"present":false,"current_user":"DESKTOP\\alice"}"#).unwrap();
        assert!(!windows_task_healthy(&absent, exe, &args));

        // Registered, enabled, exact definition: the only healthy outcome.
        assert!(windows_task_healthy(
            &healthy_windows_task(exe, &args),
            exe,
            &args
        ));

        // Registered but Disabled: never healthy.
        let mut disabled = healthy_windows_task(exe, &args);
        disabled.enabled = false;
        assert!(!windows_task_healthy(&disabled, exe, &args));

        // Wrong executable: not healthy.
        assert!(!windows_task_healthy(
            &healthy_windows_task(r"C:\Other\wayfinder.exe", &args),
            exe,
            &args
        ));

        // Wrong arguments: not healthy.
        assert!(!windows_task_healthy(
            &healthy_windows_task(exe, r#"--data-dir "C:\Other" daemon"#),
            exe,
            &args
        ));

        // Missing or foreign AtLogOn trigger: not healthy.
        let mut no_trigger = healthy_windows_task(exe, &args);
        no_trigger.triggers.clear();
        assert!(!windows_task_healthy(&no_trigger, exe, &args));

        let mut boot_trigger = healthy_windows_task(exe, &args);
        boot_trigger.triggers[0].trigger_type = "MSFT_TaskBootTrigger".to_owned();
        assert!(!windows_task_healthy(&boot_trigger, exe, &args));

        // Trigger/principal for another user: not healthy.
        let mut wrong_trigger_user = healthy_windows_task(exe, &args);
        wrong_trigger_user.triggers[0].user = Some(r"DESKTOP\bob".to_owned());
        assert!(!windows_task_healthy(&wrong_trigger_user, exe, &args));

        let mut wrong_user = healthy_windows_task(exe, &args);
        wrong_user.user = Some(r"DESKTOP\bob".to_owned());
        assert!(!windows_task_healthy(&wrong_user, exe, &args));

        // Wrong principal semantics: not healthy.
        let mut elevated = healthy_windows_task(exe, &args);
        elevated.run_level = Some("Highest".to_owned());
        assert!(!windows_task_healthy(&elevated, exe, &args));
    }

    #[test]
    fn windows_query_is_structured_and_marker_free() {
        let name = windows_ps("app.usewayfinder.agent.0123456789abcdef");
        let query = windows_query_script(&name);
        assert!(query.contains(&name));
        // Structured object properties, not localized human-readable text.
        assert!(query.contains("present=$true"));
        assert!(query.contains("Settings.Enabled"));
        assert!(query.contains("CimClassName"));
        assert!(query.contains("LogonType"));
        assert!(query.contains("ConvertTo-Json"));

        let unregister = windows_unregister_script(&name);
        assert!(unregister.contains("Unregister-ScheduledTask"));
        assert!(unregister.contains("SilentlyContinue"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_configure_round_trips_without_lifecycle() {
        let _guard = test_lock();
        let root = std::env::temp_dir().join(format!(
            "wayfinder-test-{}",
            wayfinder_core::random_secret()
        ));
        let data = root.join("data");
        let units = root.join("units");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&units).unwrap();
        *TEST_UNITS_DIR.lock().unwrap() = Some(units.clone());

        assert!(!installed(&data).unwrap());
        // Deterministic, data-directory-scoped unit name owned by Wayfinder.
        let file = definition(&data).unwrap();
        let name = file.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("app.usewayfinder.agent."));
        assert!(name.ends_with(".service"));
        // Enable registers next-login startup without any start verb.
        native_configure(&data, Configure::Enable).unwrap();
        assert!(installed(&data).unwrap());
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(" daemon\n"), "{text}");
        assert!(text.contains("ExecStart="));
        // External `systemctl --user disable` removes the link; status must reflect it.
        let _ = std::fs::remove_file(wants_link(&data).unwrap());
        assert!(!installed(&data).unwrap());
        // Re-enabling repairs the registration.
        native_configure(&data, Configure::Enable).unwrap();
        assert!(installed(&data).unwrap());
        native_configure(&data, Configure::Disable).unwrap();
        assert!(!installed(&data).unwrap());
        assert!(!definition(&data).unwrap().exists());

        *TEST_UNITS_DIR.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn macos_launch_agent_plist_binds_exact_binary_and_data_dir() {
        let root = std::env::temp_dir().join(format!(
            "wayfinder-test-{}",
            wayfinder_core::random_secret()
        ));
        let data = root.join("My Data");
        std::fs::create_dir_all(&data).unwrap();
        let text = plist_text(&data).unwrap();
        let canonical = std::fs::canonicalize(&data).unwrap();
        assert!(text.contains("<key>RunAtLoad</key><true/>"), "{text}");
        assert!(text.contains("<key>KeepAlive</key><true/>"), "{text}");
        assert!(text.contains("<string>--data-dir</string>"), "{text}");
        assert!(text.contains("<string>daemon</string>"), "{text}");
        assert!(text.contains(&xml(canonical.to_str().unwrap())), "{text}");
        assert!(text.contains("app.usewayfinder.agent."), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
