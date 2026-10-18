use crate::{
    process::LineLimited,
    runtime::{self, Runtime},
};
use anyhow::{Context, Result, ensure};
use process_wrap::tokio::ChildWrapper;
use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, Tool},
    service::RunningService,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncReadExt;
use wayfinder_core::{
    atomic_write,
    code::{OUTPUT_LIMIT, TOOLS},
    digest, private_dir,
};

pub struct Backend {
    service: RunningService<RoleClient, ()>,
    child: Child,
    pub tools: Vec<Tool>,
    pub pid: u32,
    diagnostics: Diagnostics,
    directory: PathBuf,
    _project_lock: File,
    _runtime: Runtime,
}
struct Child(Box<dyn ChildWrapper>);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}
struct Diagnostics {
    bytes: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Diagnostics {
    fn new(mut stderr: tokio::process::ChildStderr) -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = bytes.clone();
        let task = tokio::spawn(async move {
            let mut chunk = [0; 4096];
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut bytes = capture.lock().expect("diagnostic buffer");
                        bytes.extend_from_slice(&chunk[..n]);
                        let extra = bytes.len().saturating_sub(32768);
                        if extra > 0 {
                            bytes.drain(..extra);
                        }
                    }
                }
            }
        });
        Self { bytes, task }
    }
    fn save(&self, directory: &Path, error: &str) {
        let bytes = self.bytes.lock().expect("diagnostic buffer");
        let _ = atomic_write(
            &directory.join("last-error.json"),
            &json!({"error":error,"log_tail":String::from_utf8_lossy(&bytes)}),
        );
    }
}
impl Drop for Diagnostics {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn canonical_project(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute(),
        "Project must be an absolute path on the selected device"
    );
    let path =
        dunce::canonicalize(path).context("Project directory does not exist or is inaccessible")?;
    ensure!(path.is_dir(), "Project must be a directory");
    Ok(path)
}
pub fn project_directory(root: &Path, project: &Path) -> PathBuf {
    root.join("projects")
        .join(digest(project.to_string_lossy().as_bytes()))
}

impl Backend {
    pub async fn start(root: &Path, project: &Path, runtime: Runtime) -> Result<Self> {
        let directory = project_directory(root, project);
        private_dir(&directory)?;
        let project_lock = runtime::lock(&directory.join("work.lock"), false)
            .context("This project's code session is already owned by another Wayfinder process")?;
        let home = directory.join("state");
        private_dir(&home)?;
        // Pre-create this directory so upstream never adopts a repository's .serena directory.
        let metadata = directory.join("project");
        private_dir(&metadata)?;
        let configuration = json!({
            "language_backend":"LSP", "agent_interface":"tools", "web_dashboard":false,
            "web_dashboard_open_on_launch":false, "gui_log_window":false,
            "token_count_estimator":"CHAR_COUNT", "trace_lsp_communication":false,
            "log_level":30, "tool_timeout":240, "default_max_tool_answer_chars":100000,
            "project_serena_folder_location": metadata, "trusted_project_path_patterns":[],
            "base_modes":[], "default_modes":[], "fixed_tools":TOOLS, "projects":[],
            "auth_secret":wayfinder_core::random_secret()
        });
        // JSON is a strict YAML subset. All configuration is private and Wayfinder-owned.
        atomic_write(&home.join("serena_config.yml"), &configuration)?;
        let context = directory.join("context.yml");
        atomic_write(
            &context,
            &json!({"description":"Wayfinder device code tools","prompt":null,"single_project":true,"fixed_tools":TOOLS,"structured_tool_output":null}),
        )?;
        atomic_write(&directory.join("project.json"), &json!({"project":project}))?;
        prune_logs(&home.join("logs"));
        let mut command = runtime.command()?;
        command
            .command_mut()
            .args([
                "-I",
                "-c",
                "from serena.cli import top_level; top_level()",
                "start-mcp-server",
                "--transport",
                "stdio",
                "--agent-interface",
                "tools",
                "--language-backend",
                "LSP",
                "--enable-web-dashboard",
                "false",
                "--enable-gui-log-window",
                "false",
                "--open-web-dashboard",
                "false",
                "--log-level",
                "WARNING",
                "--context",
            ])
            .arg(&context)
            .arg("--project")
            .arg(project)
            .env("SERENA_HOME", &home)
            .current_dir(&directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = Child(
            command
                .spawn()
                .context("Cannot start the managed code process")?,
        );
        let pid = child.0.id().context("Code process has no process ID")?;
        let stdout = child.0.stdout().take().expect("piped stdout");
        let stdin = child.0.stdin().take().expect("piped stdin");
        let diagnostics = Diagnostics::new(child.0.stderr().take().expect("piped stderr"));
        let service = match ().serve((LineLimited::new(stdout, OUTPUT_LIMIT), stdin)).await {
            Ok(service) => service,
            Err(error) => {
                diagnostics.save(&directory, &error.to_string());
                anyhow::bail!(
                    "Code intelligence could not start. Details: {}",
                    directory.join("last-error.json").display()
                );
            }
        };
        let mut backend = Self {
            service,
            child,
            tools: Vec::new(),
            pid,
            diagnostics,
            directory,
            _project_lock: project_lock,
            _runtime: runtime,
        };
        // Limit discovery as well as wire size. Do not accept an unbounded pagination stream.
        let mut cursor = None;
        for _ in 0..8 {
            let mut params = rmcp::model::PaginatedRequestParams::default();
            params.cursor = cursor;
            let result = backend.service.list_tools(Some(params)).await?;
            for mut tool in result.tools {
                if TOOLS.contains(&tool.name.as_ref()) {
                    tool.name = format!("code_{}", tool.name).into();
                    if let Some(description) = &tool.description {
                        tool.description = Some(description.replace("Serena", "Wayfinder").into());
                    }
                    backend.tools.push(tool);
                }
            }
            ensure!(
                backend.tools.len() <= TOOLS.len(),
                "Unexpected code tool catalogue"
            );
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        ensure!(
            cursor.is_none() && !backend.tools.is_empty(),
            "Code intelligence did not expose a usable project tool catalogue"
        );
        Ok(backend)
    }
    pub async fn call(
        &self,
        tool: &str,
        arguments: serde_json::Map<String, Value>,
    ) -> Result<Value> {
        ensure!(
            self.tools.iter().any(|t| t.name == format!("code_{tool}")),
            "This tool is not supported by the active project's language backend"
        );
        let request = CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments);
        match self.service.call_tool(request).await {
            Ok(result) => {
                let result = serde_json::to_value(result)?;
                ensure!(
                    serde_json::to_vec(&result)?.len() <= OUTPUT_LIMIT - 16384,
                    "Code result exceeded 1 MiB; the operation may have completed. Do not replay edits without inspecting the files"
                );
                // Never rewrite source code, paths, memory text or structured upstream results.
                Ok(result)
            }
            Err(error) => {
                self.diagnostics.save(&self.directory, &error.to_string());
                Err(error).context(format!(
                    "Code operation interrupted; outcome may be unknown. Details: {}",
                    self.directory.join("last-error.json").display()
                ))
            }
        }
    }
    pub fn is_closed(&self) -> bool {
        self.service.is_closed()
    }
    pub fn recipe(&self) -> &str {
        &self._runtime.recipe
    }
    pub async fn stop(mut self) {
        self.service.cancellation_token().cancel();
        let _ = self.child.0.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(3), self.child.0.wait()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), self.service.close()).await;
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.service.cancellation_token().cancel();
        let _ = self.child.0.start_kill();
    }
}

fn prune_logs(root: &Path) {
    // Each project has an exclusive OS lock. Retain recent diagnostics, not an unbounded history.
    if let Ok(entries) = fs::read_dir(root) {
        let mut entries: Vec<_> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let remove = entries.len().saturating_sub(2);
        for entry in entries.into_iter().take(remove) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_named_projects_have_distinct_private_state() {
        let root = Path::new("state");
        assert_ne!(
            project_directory(root, Path::new("/a/project")),
            project_directory(root, Path::new("/b/project"))
        );
        assert!(canonical_project("relative/project").is_err());
    }
}
