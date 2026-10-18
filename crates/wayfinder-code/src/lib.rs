//! Wayfinder owns lifecycle and transport; the unchanged local backend owns code intelligence.
mod archive;
mod backend;
mod channel;
mod process;
mod qualification;
mod runtime;
pub mod updates;

use anyhow::{Context, Result, ensure};
use backend::{Backend, canonical_project};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use wayfinder_core::{
    atomic_write,
    code::{CodeAction, CodeInput, CodeResult, DEFAULT_TIMEOUT},
    private_dir, read_private,
};

const MAX_SESSIONS: usize = 4;
const IDLE: Duration = Duration::from_secs(600);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    #[serde(default = "automatic_updates_default")]
    pub automatic_updates: bool,
}
fn automatic_updates_default() -> bool {
    true
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            automatic_updates: true,
        }
    }
}
impl Settings {
    pub fn load(data: &Path) -> Result<Self> {
        let path = runtime::root(data).join("settings.json");
        if path.exists() {
            read_private(&path)
        } else {
            Ok(Self::default())
        }
    }
    pub fn set_enabled(data: &Path, enabled: bool) -> Result<()> {
        let root = runtime::root(data);
        private_dir(&root)?;
        let _lock = runtime::lock(&root.join("settings.lock"), false)?;
        let mut settings = Self::load(data)?;
        settings.enabled = enabled;
        atomic_write(&root.join("settings.json"), &settings)
    }
    pub fn set_automatic_updates(data: &Path, enabled: bool) -> Result<()> {
        let root = runtime::root(data);
        private_dir(&root)?;
        let _lock = runtime::lock(&root.join("settings.lock"), false)?;
        let mut settings = Self::load(data)?;
        settings.automatic_updates = enabled;
        atomic_write(&root.join("settings.json"), &settings)
    }
}

struct Slot {
    backend: Option<Backend>,
    touched: Instant,
}
struct Entry {
    stop: CancellationToken,
    slot: AsyncMutex<Slot>,
}
pub struct Manager {
    data: PathBuf,
    root: PathBuf,
    projects: Mutex<BTreeMap<PathBuf, Arc<Entry>>>,
    stop: CancellationToken,
}
impl Manager {
    pub fn new(data: &Path) -> Self {
        let data = std::path::absolute(data).unwrap_or_else(|_| data.to_owned());
        Self {
            root: runtime::root(&data),
            data,
            projects: Mutex::new(BTreeMap::new()),
            stop: CancellationToken::new(),
        }
    }
    pub fn status(&self) -> Result<Value> {
        let settings = Settings::load(&self.data)?;
        let projects = self.projects.lock().expect("code project registry");
        let projects: Vec<_> = projects.iter().map(|(path, entry)| {
            if let Ok(slot) = entry.slot.try_lock() {
                json!({"project":path,"busy":false,"running":slot.backend.as_ref().is_some_and(|b| !b.is_closed()),"pid":slot.backend.as_ref().map(|b|b.pid)})
            } else { json!({"project":path,"busy":true}) }
        }).collect();
        Ok(
            json!({"enabled":settings.enabled,"runtime_ready":runtime::installed(&self.root),"recipe":runtime::recipe(&self.root)?,"automatic_updates":Settings::load(&self.data)?.automatic_updates,"updates":updates::status(&self.root)?,"projects":projects,"session_limit":MAX_SESSIONS,"idle_seconds":IDLE.as_secs(),"private_data":self.root}),
        )
    }
    pub async fn execute(&self, input: CodeInput, cancel: CancellationToken) -> CodeResult {
        if let Err(error) = input.validate() {
            return CodeResult::failed(&input, error);
        }
        let sent = AtomicBool::new(false);
        let deadline = tokio::time::sleep(Duration::from_millis(
            input.timeout.unwrap_or(DEFAULT_TIMEOUT),
        ));
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return interrupted(&input, &sent, false),
            _ = self.stop.cancelled() => return interrupted(&input, &sent, false),
            _ = deadline => return interrupted(&input, &sent, true),
            _ = self.wait_disabled(), if !matches!(input.action, CodeAction::Status | CodeAction::Close) => return interrupted(&input, &sent, false),
            result = self.operation(&input, &sent) => result,
        };
        match result {
            Ok(value) => CodeResult::success(&input, value),
            Err(error) => {
                let mut result = CodeResult::failed(&input, format!("{error:#}"));
                result.outcome_unknown = sent.load(Ordering::Relaxed);
                result
            }
        }
    }
    async fn wait_disabled(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if !Settings::load(&self.data).is_ok_and(|settings| settings.enabled) {
                return;
            }
        }
    }
    fn observe(&self) {
        if self.root.exists()
            && let Ok(mut value) = self.status()
        {
            value["observed"] = json!(wayfinder_core::now());
            let _ = atomic_write(&self.root.join("status.json"), &value);
        }
    }
    async fn operation(&self, input: &CodeInput, sent: &AtomicBool) -> Result<Value> {
        if input.action == CodeAction::Status {
            return self.status();
        }
        if input.action == CodeAction::Close {
            let project = canonical_project(input.project.as_deref().expect("validated project"))?;
            let entry = self
                .projects
                .lock()
                .expect("code project registry")
                .remove(&project);
            if let Some(entry) = entry {
                self.close(entry).await;
                return Ok(json!({"closed":true}));
            }
            return Ok(json!({"closed":false}));
        }
        ensure!(
            Settings::load(&self.data)?.enabled,
            "Code intelligence is disabled in this device's Wayfinder settings"
        );
        let project = input
            .project
            .as_deref()
            .map(canonical_project)
            .transpose()?;
        if input.action == CodeAction::Prepare && project.is_none() {
            let _runtime = runtime::Runtime::ensure(&self.root).await?;
            return Ok(
                json!({"runtime_ready":true,"recipe":runtime::recipe(&self.root)?,"automatic_updates":Settings::load(&self.data)?.automatic_updates,"updates":updates::status(&self.root)?}),
            );
        }
        let project = project.context("Project directory is required")?;
        let entry = self.entry(&project)?;
        let operation = async {
            let mut slot = entry.slot.lock().await;
            slot.touched = Instant::now();
            // Move ownership out of the pool while a call is active. Dropping a cancelled
            // future kills its process tree immediately, rather than leaving an edit running.
            let backend = match slot.backend.take() {
                Some(backend) => backend,
                None => {
                    let runtime = runtime::Runtime::ensure(&self.root).await?;
                    let recipe = runtime.recipe.clone();
                    match Backend::start(&self.root, &project, runtime).await {
                        Ok(backend) => backend,
                        Err(error) => {
                            let restored = updates::rollback_failed(&self.root, &recipe).await?;
                            return Err(error.context(if restored {
                                "Previous code runtime restored for the next request. No operation was replayed"
                            } else { "Code startup failed before tool dispatch" }));
                        }
                    }
                }
            };
            if backend.is_closed() {
                let recipe = backend.recipe().to_owned();
                backend.stop().await;
                updates::rollback_failed(&self.root, &recipe).await?;
                anyhow::bail!(
                    "The code session ended. No operation was replayed; inspect previous edits before starting a new call"
                );
            }
            let result = match input.action {
                CodeAction::Prepare => Ok(
                    json!({"runtime_ready":true,"project":project,"tool_count":backend.tools.len()}),
                ),
                CodeAction::Tools => Ok(
                    json!({"project":project,"tools":backend.tools,"instructions":"Use action=call with the exact code_* tool name and arguments matching its inputSchema. Paths are relative to this project. Edits are not retried."}),
                ),
                CodeAction::Call => {
                    let tool = input.native_tool()?;
                    ensure!(
                        backend
                            .tools
                            .iter()
                            .any(|t| t.name == input.tool.as_deref().expect("validated tool")),
                        "The selected project's language backend does not support this tool"
                    );
                    sent.store(true, Ordering::Relaxed);
                    backend
                        .call(tool, input.arguments.clone().unwrap_or_default())
                        .await
                }
                CodeAction::Status | CodeAction::Close => {
                    unreachable!("handled before project activation")
                }
            };
            slot.touched = Instant::now();
            if result.is_ok() {
                slot.backend = Some(backend);
            } else {
                let recipe = backend.recipe().to_owned();
                backend.stop().await;
                updates::rollback_failed(&self.root, &recipe).await?;
            }
            result
        };
        tokio::select! {
            biased;
            _ = entry.stop.cancelled() => anyhow::bail!("Code session was closed or disabled; in-flight edits may have an unknown outcome"),
            result = operation => result,
        }
    }
    fn entry(&self, project: &Path) -> Result<Arc<Entry>> {
        let mut projects = self.projects.lock().expect("code project registry");
        if let Some(entry) = projects.get(project) {
            return Ok(entry.clone());
        }
        projects.retain(|_, entry| {
            Arc::strong_count(entry) > 1
                || !entry.slot.try_lock().is_ok_and(|s| s.backend.is_none())
        });
        ensure!(
            projects.len() < MAX_SESSIONS,
            "Code session capacity reached; close an unused project's code session"
        );
        let entry = Arc::new(Entry {
            stop: CancellationToken::new(),
            slot: AsyncMutex::new(Slot {
                backend: None,
                touched: Instant::now(),
            }),
        });
        projects.insert(project.to_owned(), entry.clone());
        Ok(entry)
    }
    async fn close(&self, entry: Arc<Entry>) {
        entry.stop.cancel();
        let mut slot = entry.slot.lock().await;
        if let Some(backend) = slot.backend.take() {
            backend.stop().await;
        }
    }
    pub async fn maintenance(&self, stop: CancellationToken) {
        loop {
            tokio::select! { _ = stop.cancelled() => break, _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
            let disabled = !Settings::load(&self.data).is_ok_and(|s| s.enabled);
            let expired: Vec<_> = {
                let mut projects = self.projects.lock().expect("code project registry");
                let keys: Vec<_> = projects
                    .iter()
                    .filter_map(|(path, entry)| {
                        let idle = Arc::strong_count(entry) == 1
                            && entry.slot.try_lock().is_ok_and(|s| {
                                s.touched.elapsed() >= IDLE
                                    || s.backend.as_ref().is_none_or(Backend::is_closed)
                            });
                        (disabled || idle).then(|| path.clone())
                    })
                    .collect();
                keys.into_iter()
                    .filter_map(|path| projects.remove(&path))
                    .collect()
            };
            for entry in expired {
                self.close(entry).await;
            }
            // Do not download unused runtimes or interrupt retained project sessions.
            if !disabled
                && Settings::load(&self.data).is_ok_and(|s| s.automatic_updates)
                && self
                    .projects
                    .lock()
                    .expect("code project registry")
                    .is_empty()
                && runtime::installed(&self.root)
                && updates::due(&self.root)
            {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = self.wait_disabled() => {},
                    _ = tokio::time::timeout(Duration::from_secs(270), runtime::Runtime::ensure(&self.root)) => {},
                }
            }
            self.observe();
        }
        self.shutdown().await;
        self.observe();
    }
    pub async fn shutdown(&self) {
        self.stop.cancel();
        let entries = std::mem::take(&mut *self.projects.lock().expect("code project registry"));
        for (_, entry) in entries {
            self.close(entry).await;
        }
    }
}
fn interrupted(input: &CodeInput, sent: &AtomicBool, timed_out: bool) -> CodeResult {
    let unknown = sent.load(Ordering::Relaxed);
    let mut result = CodeResult::failed(
        input,
        if unknown {
            "Code operation interrupted; outcome unknown. No automatic retry. Inspect files before repeating an edit"
        } else if timed_out {
            "Code operation timed out before tool dispatch"
        } else {
            "Code operation cancelled before tool dispatch"
        },
    );
    result.timed_out = timed_out;
    result.outcome_unknown = unknown;
    result
}

/// Explicit local cache removal. Project memories and all Wayfinder identity/grants survive.
pub fn clean(data: &Path) -> Result<()> {
    ensure!(
        !Settings::load(data)?.enabled,
        "Disable code intelligence before cleaning its runtime cache"
    );
    let root = runtime::root(data);
    private_dir(&root)?;
    let _install = runtime::lock(&root.join("install.lock"), false)
        .context("Code runtime setup is in progress")?;
    let _use = runtime::lock(&root.join("use.lock"), false)
        .context("Code sessions are still stopping; runtime cache has not been changed")?;
    for name in ["runtimes", "python", "cache", "downloads", "update-probe"] {
        let path = root.join(name);
        if path.exists() {
            fs::remove_dir_all(path)?;
        }
    }
    if let Ok(projects) = fs::read_dir(root.join("projects")) {
        for project in projects {
            let project = project?;
            if !project.file_type()?.is_dir() {
                continue;
            }
            for relative in ["state/language_servers", "state/logs", "project/cache"] {
                let cache = project.path().join(relative);
                if cache.exists() {
                    fs::remove_dir_all(cache)?;
                }
            }
        }
    }
    let _ = fs::remove_file(root.join("setup-error.json"));
    Ok(())
}

/// Cached running-session observations are display-only, never configuration or authority.
pub fn local_status(data: &Path) -> Result<Value> {
    let mut status = Manager::new(data).status()?;
    if let Ok(observed) = read_private::<Value>(&runtime::root(data).join("status.json"))
        && observed["observed"]
            .as_u64()
            .is_some_and(|t| t <= wayfinder_core::now() && wayfinder_core::now() - t <= 10)
        && observed["projects"].is_array()
    {
        status["projects"] = observed["projects"].clone();
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "wayfinder-code-{}",
            wayfinder_core::random_secret()
        ))
    }
    fn input(action: CodeAction) -> CodeInput {
        CodeInput {
            target: "local".into(),
            action,
            project: None,
            tool: None,
            arguments: None,
            timeout: None,
        }
    }
    #[tokio::test]
    async fn status_does_not_install_or_create_state() {
        let data = temp();
        let manager = Manager::new(&data);
        let result = manager
            .execute(input(CodeAction::Status), CancellationToken::new())
            .await;
        assert!(!result.is_error());
        assert_eq!(result.result.unwrap()["runtime_ready"], false);
        assert!(!data.exists());
    }
    #[tokio::test]
    async fn disable_prevents_downloads_and_preserves_project_memories() {
        let data = temp();
        Settings::set_enabled(&data, false).unwrap();
        let project = runtime::root(&data).join("projects/example");
        private_dir(&project).unwrap();
        fs::write(project.join("memory.md"), "retain").unwrap();
        let manager = Manager::new(&data);
        let result = manager
            .execute(input(CodeAction::Prepare), CancellationToken::new())
            .await;
        assert!(result.is_error());
        assert!(!runtime::root(&data).join("downloads").exists());
        clean(&data).unwrap();
        assert_eq!(
            fs::read_to_string(project.join("memory.md")).unwrap(),
            "retain"
        );
        fs::remove_dir_all(data).unwrap();
    }
    #[tokio::test]
    async fn pre_cancelled_calls_never_provision() {
        let data = temp();
        let manager = Manager::new(&data);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = manager.execute(input(CodeAction::Prepare), cancel).await;
        assert!(result.is_error());
        assert!(!result.outcome_unknown);
        assert!(!data.exists());
    }
}
