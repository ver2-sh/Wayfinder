//! Optional release discovery; never coupled to gateway authentication or agent operation.
use anyhow::{Context, Result, ensure};
use axoupdater::{AxoUpdater, ReleaseSource, ReleaseSourceType};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};
use wayfinder_core::{atomic_write, now, private_dir, read_private};

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
// Official release origin, independent of the user's gateway. Future mirrors belong here
// and in dist-workspace.toml, never in identity or gateway configuration.
const OWNER: &str = "Made-by-Eugene";
const REPOSITORY: &str = "project-wayfinder";
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
    u.set_client(
        update_http::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?,
    );
    if receipt {
        // axoupdater uses process-scoped PowerShell Bypass on Windows. It does
        // not persist policy changes; MachinePolicy/UserPolicy take precedence.
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
        Ok(Ok(latest))=>{state.latest=latest;state.error=None;}
        _=>state.error=Some("release channel inaccessible (private repository, no release, network failure or rate limit). Agent operation is unaffected".into()),
    }
    atomic_write(&path, &state)?;
    Ok(state)
}
pub async fn install(data: &Path) -> Result<()> {
    let mut u = updater(true)?;
    // Complete discovery before interrupting any agent. axoupdater retains this exact release.
    ensure!(
        tokio::time::timeout(Duration::from_secs(30), u.is_update_needed()).await??,
        "No newer stable release"
    );
    let restart = crate::service::agent_running(data)?;
    if restart {
        ensure!(
            crate::service::installed(data)?,
            "Stop the independently launched daemon before updating"
        );
        crate::service::manage(data, crate::service::Action::Stop)?;
    }
    let result = async {
        if restart {
            crate::service::wait_stopped(data).await?;
        }
        let _lock = wayfinder_core::lock_dir(data)?;
        ensure!(
            u.run()
                .await
                .context(if cfg!(windows) {
                    "Update failed; identity and configuration were not changed. If PowerShell reports an organizational MachinePolicy/UserPolicy restriction, contact your administrator; Wayfinder does not override Group Policy or change persistent execution policy"
                } else {
                    "Update failed; user identity and configuration were not changed"
                })?
                .is_some(),
            "No binary replacement was performed"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Restart even after a failed update; surface both failures if needed.
    if restart && let Err(e) = crate::service::manage(data, crate::service::Action::Start) {
        anyhow::bail!(
            "Update result: {result:?}; agent restart failed: {e:#}. Run wayfinder service start"
        );
    }
    result?;
    println!("Updated. Exit and reopen Wayfinder to use the new version.");
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
