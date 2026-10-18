//! Independent, opt-out backend updates. Never update an environment in place and
//! never retry a user tool call. The previous runtime is restored for future sessions.
use crate::{
    channel::{self, Manifest, Pins},
    runtime,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, future::Future, path::Path, time::Duration};
use wayfinder_core::{atomic_write, now, read_private};

pub const CHECK_INTERVAL: u64 = 86400;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    checked_at: u64,
    highest_sequence: u64,
    manifest_id: Option<String>,
    offered: Option<Manifest>,
    active: Option<Pins>,
    previous: Option<Pins>,
    rejected: Option<String>,
    last_error: Option<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 1,
            checked_at: 0,
            highest_sequence: 0,
            manifest_id: None,
            offered: None,
            active: None,
            previous: None,
            rejected: None,
            last_error: None,
        }
    }
}
impl State {
    fn load(root: &Path) -> Result<Self> {
        let file = root.join("updates.json");
        if !file.exists() {
            return Ok(Self::default());
        }
        ensure!(
            fs::metadata(&file)?.len() <= channel::MAX_BYTES as u64,
            "Code update state exceeds limit"
        );
        let state: Self = read_private(&file)?;
        ensure!(state.schema == 1, "Unsupported code update state");
        for pins in [&state.active, &state.previous].into_iter().flatten() {
            pins.validate()?;
        }
        if let Some(manifest) = &state.offered {
            manifest.validate()?;
            ensure!(
                manifest.sequence == state.highest_sequence
                    && Some(manifest.id()) == state.manifest_id,
                "Code update state has inconsistent release identity"
            );
        }
        if let Some(id) = &state.rejected {
            ensure!(channel::hex_id(id, 64), "Invalid rejected runtime identity");
        }
        Ok(state)
    }
    fn save(&self, root: &Path) -> Result<()> {
        atomic_write(&root.join("updates.json"), self)
    }
    fn selected(&self) -> Pins {
        self.active.clone().unwrap_or_else(channel::embedded)
    }
    fn due(&self) -> bool {
        self.checked_at == 0 || self.checked_at > now() || now() - self.checked_at >= CHECK_INTERVAL
    }
    fn accept(&mut self, offered: Manifest) -> Result<()> {
        offered.validate()?;
        ensure!(
            offered.sequence >= self.highest_sequence,
            "Refusing an older code runtime release sequence"
        );
        if offered.sequence == self.highest_sequence {
            ensure!(
                self.manifest_id.as_deref() == Some(offered.id().as_str()),
                "A code runtime release sequence cannot change contents"
            );
        }
        self.highest_sequence = offered.sequence;
        self.manifest_id = Some(offered.id());
        self.offered = Some(offered);
        self.last_error = None;
        Ok(())
    }
}
pub(crate) fn active(root: &Path) -> Result<Pins> {
    Ok(State::load(root)?.selected())
}
pub(crate) fn due(root: &Path) -> bool {
    State::load(root).is_ok_and(|s| s.due() || pending(&s))
}
fn pending(state: &State) -> bool {
    state.offered.as_ref().is_some_and(|m| {
        m.pins.id() != state.selected().id()
            && state.rejected.as_deref() != Some(m.pins.id().as_str())
    })
}
pub fn status(root: &Path) -> Result<Value> {
    let state = State::load(root)?;
    let pins = state.selected();
    Ok(
        json!({"channel":channel::URL,"integration":channel::INTEGRATION,
        "active_version":pins.package_version,"active_recipe":pins.id(),
        "previous_version":state.previous.as_ref().map(|p|&p.package_version),
        "offered_version":state.offered.as_ref().map(|m|&m.pins.package_version),
        "update_pending":pending(&state),"last_check":state.checked_at,
        "check_interval_seconds":CHECK_INTERVAL,"release_sequence":state.highest_sequence,
        "rejected_recipe":state.rejected,"last_error":state.last_error}),
    )
}

/// Caller owns install.lock. A cached/network failure retains the selected runtime.
pub(crate) async fn refresh_locked(root: &Path, force: bool, check_only: bool) -> Result<()> {
    refresh_with(
        root,
        force,
        check_only,
        channel::fetch(),
        |pins| async move { crate::qualification::qualify(root, pins).await },
    )
    .await
}
async fn refresh_with<F, Q, R>(
    root: &Path,
    force: bool,
    check_only: bool,
    fetch: F,
    qualify: Q,
) -> Result<()>
where
    F: Future<Output = Result<Manifest>>,
    Q: FnOnce(Pins) -> R,
    R: Future<Output = Result<()>>,
{
    let mut state = State::load(root)?;
    if force || state.due() {
        // Persist attempts before the network call, including interrupted and failed checks.
        state.checked_at = now();
        state.save(root)?;
        let result = fetch.await.and_then(|manifest| state.accept(manifest));
        if let Err(error) = result {
            state.last_error = Some(format!("{error:#}"));
        }
        state.save(root)?;
    }
    if check_only || !pending(&state) {
        return Ok(());
    }
    // All code processes retain this lease. Defer upgrades until they are idle/closed;
    // do not terminate a live process or replace its environment to install an update.
    match runtime::lock(&root.join("use.lock"), false) {
        Ok(lease) => drop(lease),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error.context("Cannot check code runtime leases")),
    }
    let candidate = state.offered.as_ref().expect("pending offer").pins.clone();
    let previous = state.selected();
    let result = tokio::time::timeout(Duration::from_secs(240), qualify(candidate.clone()))
        .await
        .context("Code runtime qualification timed out")
        .and_then(|r| r);
    match result {
        Ok(()) => {
            state.previous = runtime::installed_pins(root, &previous).then_some(previous);
            state.active = Some(candidate);
            state.last_error = None;
            state.rejected = None;
        }
        Err(error) => {
            state.rejected = Some(candidate.id());
            state.last_error = Some(format!(
                "Code runtime update rejected; working version retained: {error:#}"
            ));
        }
    }
    state.save(root)?;
    prune(root, &state);
    Ok(())
}

/// Explicit checks/installations use the same implementation as automatic updates.
pub async fn update(data: &Path, check_only: bool) -> Result<Value> {
    ensure!(
        crate::Settings::load(data)?.enabled,
        "Code intelligence is disabled"
    );
    let root = runtime::root(data);
    wayfinder_core::private_dir(&root)?;
    let _install = runtime::installation_lock(&root).await?;
    refresh_locked(&root, true, check_only).await?;
    status(&root)
}
/// Restore only a previously installed runtime, and quarantine the failed candidate.
/// No operation is dispatched here; callers must return the original failure, not replay it.
pub(crate) async fn rollback_failed(root: &Path, failed_recipe: &str) -> Result<bool> {
    let _install = runtime::installation_lock(root).await?;
    let mut state = State::load(root)?;
    if state
        .active
        .as_ref()
        .is_none_or(|p| p.id() != failed_recipe)
    {
        return Ok(false);
    }
    let Some(previous) = state
        .previous
        .clone()
        .filter(|p| runtime::installed_pins(root, p))
    else {
        return Ok(false);
    };
    state.active = Some(previous);
    state.previous = None;
    state.rejected = Some(failed_recipe.into());
    state.last_error = Some(
        "Code runtime rolled back after a process/startup failure. No tool call was replayed"
            .into(),
    );
    state.save(root)?;
    Ok(true)
}
pub async fn rollback(data: &Path) -> Result<Value> {
    let root = runtime::root(data);
    let selected = active(&root)?;
    ensure!(
        rollback_failed(&root, &selected.id()).await?,
        "No previous installed code runtime is available"
    );
    status(&root)
}
fn prune(root: &Path, state: &State) {
    // Never delete an environment while any code process owns a runtime lease.
    let Ok(_unused) = runtime::lock(&root.join("use.lock"), false) else {
        return;
    };
    let active = state.selected().id();
    let previous = state.previous.as_ref().map(Pins::id);
    if let Ok(entries) = fs::read_dir(root.join("runtimes")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if channel::hex_id(&name, 64)
                && name != active
                && previous.as_deref() != Some(&name)
                && entry.file_type().is_ok_and(|t| t.is_dir())
            {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wayfinder-updates-{}",
            wayfinder_core::random_secret()
        ));
        wayfinder_core::private_dir(&root).unwrap();
        root
    }
    fn manifest(sequence: u64) -> Manifest {
        let mut pins = channel::embedded();
        pins.package_version = format!("2.0.{sequence}");
        Manifest {
            schema: 1,
            integration: channel::INTEGRATION,
            sequence,
            pins,
        }
    }
    #[test]
    fn sequence_is_monotonic_and_immutable() {
        let mut state = State::default();
        state.accept(manifest(3)).unwrap();
        assert!(state.accept(manifest(2)).is_err());
        let mut changed = manifest(3);
        changed.pins.package_version = "9.0.0".into();
        assert!(state.accept(changed).is_err());
        state.accept(manifest(3)).unwrap();
        assert_eq!(state.highest_sequence, 3);
    }
    #[tokio::test]
    async fn offline_and_rejected_updates_keep_active_and_do_not_retry() {
        let root = root();
        refresh_with(
            &root,
            false,
            false,
            async { anyhow::bail!("offline") },
            |_| async { panic!("must not install") },
        )
        .await
        .unwrap();
        assert_eq!(active(&root).unwrap(), channel::embedded());
        assert!(
            status(&root).unwrap()["last_error"]
                .as_str()
                .unwrap()
                .contains("offline")
        );
        refresh_with(
            &root,
            false,
            false,
            async { panic!("failed check must be cached") },
            |_| async { panic!("must not install") },
        )
        .await
        .unwrap();
        refresh_with(&root, true, false, async { Ok(manifest(2)) }, |_| async {
            anyhow::bail!("bad MCP")
        })
        .await
        .unwrap();
        assert_eq!(active(&root).unwrap(), channel::embedded());
        assert_eq!(
            State::load(&root).unwrap().rejected,
            Some(manifest(2).pins.id())
        );
        refresh_with(&root, true, false, async { Ok(manifest(2)) }, |_| async {
            panic!("rejected recipe must not be retried")
        })
        .await
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn live_sessions_defer_updates_and_check_only_never_installs() {
        let root = root();
        refresh_with(&root, true, true, async { Ok(manifest(2)) }, |_| async {
            panic!("check-only installed")
        })
        .await
        .unwrap();
        assert!(pending(&State::load(&root).unwrap()));
        let lease = runtime::lock(&root.join("use.lock"), true).unwrap();
        refresh_with(&root, false, false, async { panic!("cached") }, |_| async {
            panic!("live session was interrupted")
        })
        .await
        .unwrap();
        drop(lease);
        refresh_with(&root, false, false, async { panic!("cached") }, |_| async {
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(active(&root).unwrap(), manifest(2).pins);
        assert!(!pending(&State::load(&root).unwrap()));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn corrupt_state_fails_closed_and_status_is_read_only() {
        let root = root();
        let missing = root.join("missing");
        assert!(status(&missing).is_ok());
        assert!(!missing.exists());
        fs::write(root.join("updates.json"), b"not json").unwrap();
        assert!(active(&root).is_err());
        assert!(status(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    // Synthetic installations exercise the state machine without executing/downloading tools.
    fn installed_fixture(root: &Path, pins: &Pins) {
        let directory = root.join("runtimes").join(pins.id());
        let python = directory.join(if cfg!(windows) {
            "environment/Scripts/python.exe"
        } else {
            "environment/bin/python"
        });
        let node = directory.join(if cfg!(windows) {
            "node/node.exe"
        } else {
            "node/bin/node"
        });
        for file in [&python, &node] {
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, b"synthetic test file; not executable").unwrap();
        }
        atomic_write(&directory.join("ready.json"), &json!({"recipe":pins.id()})).unwrap();
    }

    #[tokio::test]
    async fn successful_update_retains_previous_and_rollback_quarantines() {
        let root = root();
        let previous = channel::embedded();
        let candidate = manifest(2);
        installed_fixture(&root, &previous);
        installed_fixture(&root, &manifest(99).pins);
        let memory = root.join("projects/example/project/memories/keep.md");
        fs::create_dir_all(memory.parent().unwrap()).unwrap();
        fs::write(&memory, "unchanged user memory").unwrap();
        refresh_with(
            &root,
            true,
            false,
            async { Ok(candidate.clone()) },
            |pins| {
                assert_eq!(
                    active(&root).unwrap(),
                    previous,
                    "Activation must follow qualification"
                );
                installed_fixture(&root, &pins);
                std::future::ready(Ok(()))
            },
        )
        .await
        .unwrap();
        let state = State::load(&root).unwrap();
        assert_eq!(state.active, Some(candidate.pins.clone()));
        assert_eq!(state.previous, Some(previous.clone()));
        assert!(!root.join("runtimes").join(manifest(99).pins.id()).exists());
        assert!(runtime::installed_pins(&root, &previous));
        // Rollback changes only the pointer for later sessions, not running environments.
        let lease = runtime::lock(&root.join("use.lock"), true).unwrap();
        assert!(rollback_failed(&root, &candidate.pins.id()).await.unwrap());
        assert_eq!(active(&root).unwrap(), previous);
        assert!(runtime::installed_pins(&root, &candidate.pins));
        drop(lease);
        refresh_with(
            &root,
            true,
            false,
            async { Ok(candidate.clone()) },
            |_| async {
                panic!("A rolled-back candidate must not be installed again automatically")
            },
        )
        .await
        .unwrap();
        assert_eq!(active(&root).unwrap(), previous);
        assert_eq!(
            State::load(&root).unwrap().rejected,
            Some(candidate.pins.id())
        );
        assert_eq!(fs::read_to_string(memory).unwrap(), "unchanged user memory");
        assert!(!rollback_failed(&root, &candidate.pins.id()).await.unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn interrupted_qualification_does_not_activate_candidate() {
        let root = root();
        let previous = channel::embedded();
        installed_fixture(&root, &previous);
        let operation = refresh_with(&root, true, false, async { Ok(manifest(2)) }, |_| {
            std::future::pending::<Result<()>>()
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(30), operation)
                .await
                .is_err()
        );
        let state = State::load(&root).unwrap();
        assert_eq!(state.selected(), previous);
        assert!(state.active.is_none());
        assert!(state.previous.is_none());
        assert!(pending(&state));
        assert!(runtime::installed_pins(&root, &previous));
        fs::remove_dir_all(root).unwrap();
    }
}
