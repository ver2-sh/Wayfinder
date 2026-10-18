//! Device-local code operations. All operations require the existing exec grant.
use anyhow::{Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const CODE_SESSION_VERSION: u32 = 3;
pub const INPUT_LIMIT: usize = 65536;
pub const OUTPUT_LIMIT: usize = 1024 * 1024;
pub const DEFAULT_TIMEOUT: u64 = 270_000;

/// Reviewed upstream tools; never forward lifecycle, dashboard, shell or REPL tools.
pub const TOOLS: &[&str] = &[
    "read_file",
    "create_text_file",
    "list_dir",
    "find_file",
    "replace_content",
    "replace_in_files",
    "delete_lines",
    "replace_lines",
    "insert_at_line",
    "search_for_pattern",
    "restart_language_server",
    "get_symbols_overview",
    "find_symbol",
    "find_referencing_symbols",
    "find_implementations",
    "find_declaration",
    "get_diagnostics_for_file",
    "get_diagnostics_for_symbol",
    "replace_symbol_body",
    "insert_after_symbol",
    "insert_before_symbol",
    "rename_symbol",
    "write_memory",
    "read_memory",
    "list_memories",
    "delete_memory",
    "rename_memory",
    "edit_memory",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeAction {
    Status,
    Prepare,
    Tools,
    Call,
    Close,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeInput {
    /// Stable device ID or unique name in the authorized chain.
    pub target: String,
    pub action: CodeAction,
    /// Absolute project directory on that device. Required for tools, call and close.
    pub project: Option<String>,
    /// Exact code_* name returned by action=tools.
    pub tool: Option<String>,
    /// Arguments matching the discovered tool's inputSchema.
    pub arguments: Option<Map<String, Value>>,
    /// Total deadline, including installation and queueing, in milliseconds (1..300000).
    pub timeout: Option<u64>,
}
impl CodeInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.target.trim().is_empty()
                && self.target.len() <= 256
                && !self.target.contains('\0'),
            "Explicit device target required"
        );
        ensure!(
            (1..=300_000).contains(&self.timeout.unwrap_or(DEFAULT_TIMEOUT)),
            "Timeout must be 1–300000 ms"
        );
        if let Some(p) = &self.project {
            ensure!(
                !p.trim().is_empty() && p.len() <= 8192 && !p.contains('\0'),
                "Invalid project directory"
            );
        }
        if matches!(
            self.action,
            CodeAction::Tools | CodeAction::Call | CodeAction::Close
        ) {
            ensure!(
                self.project.is_some(),
                "An absolute project directory is required"
            );
        }
        if self.action == CodeAction::Call {
            self.native_tool()?;
        } else {
            ensure!(
                self.tool.is_none() && self.arguments.is_none(),
                "Tool and arguments are only valid for action=call"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= INPUT_LIMIT,
            "Code request exceeds 64 KiB"
        );
        Ok(())
    }
    pub fn native_tool(&self) -> Result<&str> {
        let name = self.tool.as_deref().and_then(|s| s.strip_prefix("code_"));
        ensure!(
            name.is_some_and(|n| TOOLS.contains(&n)),
            "Use an available code_* tool returned by action=tools"
        );
        Ok(name.expect("validated tool"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeResult {
    pub target: String,
    pub project: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub timed_out: bool,
    pub outcome_unknown: bool,
}
impl CodeResult {
    pub fn success(input: &CodeInput, result: Value) -> Self {
        Self {
            target: input.target.clone(),
            project: input.project.clone(),
            result: Some(result),
            error: None,
            timed_out: false,
            outcome_unknown: false,
        }
    }
    pub fn failed(input: &CodeInput, error: impl ToString) -> Self {
        Self {
            target: input.target.clone(),
            project: input.project.clone(),
            result: None,
            error: Some(error.to_string()),
            timed_out: false,
            outcome_unknown: false,
        }
    }
    pub fn is_error(&self) -> bool {
        self.error.is_some() || self.result.as_ref().is_some_and(|v| v["isError"] == true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> CodeInput {
        CodeInput {
            target: "device".into(),
            action: CodeAction::Call,
            project: Some("/project".into()),
            tool: Some("code_find_symbol".into()),
            arguments: None,
            timeout: None,
        }
    }
    #[test]
    fn rejects_control_tools_and_malformed_requests() {
        let mut i = input();
        assert!(i.validate().is_ok());
        for tool in [
            "find_symbol",
            "code_activate_project",
            "code_serena_repl",
            "code_execute_shell_command",
            "code_open_dashboard",
        ] {
            i.tool = Some(tool.into());
            assert!(i.validate().is_err());
        }
        i = input();
        i.target.clear();
        assert!(i.validate().is_err());
        i = input();
        i.project = None;
        assert!(i.validate().is_err());
        i = input();
        i.timeout = Some(300001);
        assert!(i.validate().is_err());
        i = input();
        i.action = CodeAction::Status;
        assert!(i.validate().is_err());
        i = input();
        i.arguments = Some(Map::from_iter([(
            "body".into(),
            Value::String("x".repeat(INPUT_LIMIT)),
        )]));
        assert!(i.validate().is_err());
    }
    #[test]
    fn upstream_errors_stay_errors() {
        assert!(CodeResult::success(&input(), serde_json::json!({"isError":true})).is_error());
        assert!(!CodeResult::success(&input(), serde_json::json!({"content":[]})).is_error());
    }
}
