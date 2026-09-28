//! Optional release discovery; never coupled to gateway authentication or agent operation.
use anyhow::{Context, Result, ensure};
use axoupdater::{AxoUpdater, ReleaseSource, ReleaseSourceType};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use wayfinder_core::{atomic_write, now, private_dir, read_private};

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
// Official release origin, independent of the user's gateway. Future mirrors belong here
// and in dist-workspace.toml, never in identity or gateway configuration.
const OWNER: &str = "ver2-sh";
const REPOSITORY: &str = "Wayfinder";
#[derive(Serialize, Deserialize, Clone)]
pub struct State {
    checked: u64,
    latest: Option<String>,
    error: Option<String>,
}
impl State {
    pub fn available(&self) -> bool {
        if self.error.is_some() {
            return false;
        }
        self.latest
            .as_ref()
            .and_then(|s| semver::Version::parse(s).ok())
            .is_some_and(|v| {
                v.pre.is_empty() && v > semver::Version::parse(CURRENT).expect("package version")
            })
    }
    pub fn message(&self) -> String {
        if let Some(error) = &self.error {
            return format!("Wayfinder {CURRENT}; update check unavailable: {error}");
        }
        format!(
            "Wayfinder {CURRENT}; latest stable: {}{}",
            self.latest.as_deref().unwrap_or("no published release"),
            if self.available() {
                " — update available"
            } else {
                ""
            }
        )
    }
}
fn updater(receipt: bool) -> Result<AxoUpdater> {
    let mut u = AxoUpdater::new_for("wayfinder");
    // Capture diagnostics for errors without corrupting a live TUI or CLI output.
    u.disable_installer_output();
    u.set_client(
        update_http::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
    );
    if receipt {
        u.load_receipt().context("No direct-install receipt. Upgrade using the package manager or source/manual installation method that owns this binary")?;
        ensure!(
            u.check_receipt_is_for_this_executable()?,
            "Receipt belongs to another executable. Use the package manager that installed this copy (for example brew upgrade wayfinder); this binary will not be overwritten"
        );
    }
    u.set_release_source(ReleaseSource {
        release_type: ReleaseSourceType::GitHub,
        owner: OWNER.into(),
        name: REPOSITORY.into(),
        app_name: "wayfinder".into(),
    });
    u.set_current_version(CURRENT.parse()?)?;
    Ok(u)
}
pub fn ensure_owned() -> Result<()> {
    updater(true)?;
    Ok(())
}

pub async fn check(data: &Path, force: bool) -> Result<State> {
    private_dir(data)?;
    let path = data.join("update-check.json");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(data.join("update-check.lock"))?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            return Ok(read_private(&path).unwrap_or(State {
                checked: now(),
                latest: None,
                error: Some("another update check is in progress".into()),
            }));
        }
        Err(e) => return Err(e.into()),
    }

    if !force
        && let Ok(state) = read_private::<State>(&path)
        && now().saturating_sub(state.checked) < 86400
    {
        return Ok(state);
    }
    // Reserve the daily attempt before networking, including failures and concurrent TUIs.
    let mut state = State {
        checked: now(),
        latest: None,
        error: Some("check pending or interrupted".into()),
    };
    atomic_write(&path, &state)?;
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        Ok::<_, anyhow::Error>(
            updater(false)?
                .query_new_version()
                .await?
                .map(ToString::to_string),
        )
    })
    .await;
    match result {
        Ok(Ok(latest)) => {
            state.latest = latest;
            state.error = None;
        }
        _ => {
            state.error = Some(
                "release channel inaccessible (private repository, no release, network failure or rate limit). Agent operation is unaffected".into(),
            );
        }
    }
    atomic_write(&path, &state)?;
    Ok(state)
}
pub async fn install(data: &Path) -> Result<()> {
    use std::io::IsTerminal;
    let executable = std::env::current_exe()?;
    let prepared = prepare().await?;
    install_quiet(data, prepared).await?;
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return relaunch(&executable, data);
    }
    println!("Updated. Exit and reopen Wayfinder to use the new version.");
    Ok(())
}

pub fn relaunch(executable: &Path, data: &Path) -> Result<()> {
    let mut command = std::process::Command::new(executable);
    // Preserve the selected identity, but never replay the update command.
    command.arg("--data-dir").arg(data);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(command.exec()).context("Wayfinder updated, but restarting the app failed")
    }
    #[cfg(not(unix))]
    {
        // Let the new app inherit the console and the old process exit immediately.
        command
            .spawn()
            .context("Wayfinder updated, but restarting the app failed")?;
        Ok(())
    }
}
pub struct PreparedUpdate {
    updater: AxoUpdater,
    #[cfg(windows)]
    target: semver::Version,
    #[cfg(windows)]
    executable: std::path::PathBuf,
}

pub async fn prepare() -> Result<PreparedUpdate> {
    let mut u = updater(true)?;
    // Complete discovery before interrupting any agent. axoupdater retains this exact release.
    let target = tokio::time::timeout(Duration::from_secs(30), u.query_new_version())
        .await
        .context("Release discovery timed out")?
        .context("Release discovery failed")?
        .context("No stable release")?
        .to_string()
        .parse::<semver::Version>()?;
    ensure!(
        target.pre.is_empty() && target > semver::Version::parse(CURRENT)?,
        "No newer stable release"
    );
    Ok(PreparedUpdate {
        updater: u,
        #[cfg(windows)]
        target,
        #[cfg(windows)]
        executable: std::env::current_exe()?.canonicalize()?,
    })
}

pub async fn install_quiet(data: &Path, mut prepared: PreparedUpdate) -> Result<()> {
    let restart = crate::service::agent_running(data)?;
    if restart {
        ensure!(
            crate::service::installed(data)?,
            "Stop the independently launched daemon before updating"
        );
        crate::service::manage_quiet(data, crate::service::Action::Stop)?;
    }
    let result = async {
        if restart {
            crate::service::wait_stopped(data).await?;
        }
        let _lock = wayfinder_core::lock_dir(data)?;
        match prepared.updater.run().await {
            Ok(result) => ensure!(result.is_some(), "No binary replacement was performed"),
            #[cfg(windows)]
            Err(error @ axoupdater::AxoupdateError::CleanupFailed {}) => {
                if let Err(verification) =
                    verify_installed(&prepared.target, &prepared.executable).await
                {
                    let context = format!(
                        "Update cleanup failed: {error}; post-install verification failed: {verification:#}"
                    );
                    return Err(anyhow::Error::new(error).context(context));
                }
            }
            Err(error) => {
                return Err(anyhow::Error::new(error).context("Application update failed"));
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Restart even after a failed update; surface both failures if needed.
    if restart && let Err(e) = crate::service::manage_quiet(data, crate::service::Action::Start) {
        anyhow::bail!(
            "Update result: {result:?}; agent restart failed: {e:#}. Run wayfinder service start"
        );
    }
    result?;
    Ok(())
}

// Keep this lookup aligned with axoupdater 0.10.2's private receipt resolver:
// overrides are directories, and the first existing receipt wins even if invalid.
#[cfg(windows)]
fn receipt_path() -> Result<std::path::PathBuf> {
    use std::{env, path::PathBuf};
    let paths = if env::var("AXOUPDATER_CONFIG_WORKING_DIR").is_ok() {
        let path = env::current_dir()?;
        ensure!(path.to_str().is_some(), "Receipt directory is not UTF-8");
        vec![path]
    } else if let Ok(path) = env::var("AXOUPDATER_CONFIG_PATH") {
        vec![PathBuf::from(path)]
    } else {
        let mut paths = Vec::new();
        if let Ok(path) = env::var("XDG_CONFIG_HOME") {
            let path = PathBuf::from(path).join("wayfinder");
            if path.exists() {
                paths.push(path);
            }
        }
        if let Ok(path) = env::var("LOCALAPPDATA") {
            paths.push(PathBuf::from(path).join("wayfinder"));
        }
        paths
    };
    paths
        .into_iter()
        .map(|path| path.join("wayfinder-receipt.json"))
        .find(|path| path.exists())
        .context("No Wayfinder install receipt found after installation")
}

#[cfg(windows)]
async fn verify_installed(target: &semver::Version, executable: &Path) -> Result<()> {
    #[derive(Deserialize)]
    struct Provider {
        source: String,
        version: String,
    }
    #[derive(Deserialize)]
    struct Receipt {
        source: ReleaseSource,
        provider: Provider,
        version: String,
        binaries: Vec<String>,
        #[serde(default)]
        cdylibs: Vec<String>,
        #[serde(default)]
        cstaticlibs: Vec<String>,
        install_layout: String,
        install_prefix: std::path::PathBuf,
    }
    let path = receipt_path()?;
    let receipt: Receipt = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("Reading receipt {}", path.display()))?,
    )
    .with_context(|| format!("Parsing receipt {}", path.display()))?;
    ensure!(
        receipt.source.release_type == ReleaseSourceType::GitHub
            && receipt.source.owner == OWNER
            && receipt.source.name == REPOSITORY
            && receipt.source.app_name == "wayfinder",
        "Receipt is not from the official Wayfinder GitHub source"
    );
    ensure!(
        receipt.provider.source == "cargo-dist",
        "Receipt provider is not cargo-dist"
    );
    semver::Version::parse(&receipt.provider.version)
        .context("Invalid cargo-dist provider version")?;
    ensure!(
        semver::Version::parse(&receipt.version).context("Invalid receipt version")? == *target,
        "Receipt version does not match target {target}"
    );
    ensure!(
        receipt.binaries == ["wayfinder.exe"]
            && receipt.cdylibs.is_empty()
            && receipt.cstaticlibs.is_empty()
            && receipt.install_layout == "cargo-home",
        "Receipt must contain only wayfinder.exe in cargo-home layout, without libraries"
    );
    let installed = receipt
        .install_prefix
        .join("bin")
        .join("wayfinder.exe")
        .canonicalize()
        .context("Resolving receipt executable")?;
    ensure!(
        installed == executable,
        "Receipt executable does not match the captured executable"
    );
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(executable)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Installed executable --version timed out")?
    .context("Running installed executable --version")?;
    ensure!(
        output.status.success(),
        "Installed executable --version failed: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = std::str::from_utf8(&output.stdout).context("Version output is not UTF-8")?;
    // clap terminates its one-line version output with a newline.
    let version = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    ensure!(
        version == format!("wayfinder {target}"),
        "Unexpected installed version output: {stdout:?}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_newer_valid_versions_are_updates() {
        for (latest, expected) in [
            (CURRENT, false),
            ("0.0.1", false),
            ("999.0.0", true),
            ("invalid", false),
            ("999.0.0-beta.1", false),
        ] {
            assert_eq!(
                State {
                    checked: 0,
                    latest: Some(latest.into()),
                    error: None
                }
                .available(),
                expected
            );
        }
    }
    #[tokio::test]
    async fn failed_checks_are_cached_without_network() {
        let data = std::env::temp_dir().join(format!(
            "wayfinder-cache-{}",
            wayfinder_core::random_secret()
        ));
        private_dir(&data).unwrap();
        atomic_write(
            &data.join("update-check.json"),
            &State {
                checked: now(),
                latest: None,
                error: Some("offline".into()),
            },
        )
        .unwrap();
        assert!(
            check(&data, false)
                .await
                .unwrap()
                .message()
                .contains("offline")
        );
        std::fs::remove_dir_all(data).unwrap();
    }
}
