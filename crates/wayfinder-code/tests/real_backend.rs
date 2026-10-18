//! Explicit integration test: downloads the pinned backend, never run by ordinary cargo test.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;
use wayfinder_code::Manager;
use wayfinder_core::code::{CodeAction, CodeInput};

fn input(
    project: &Path,
    action: CodeAction,
    tool: Option<&str>,
    arguments: Option<Value>,
) -> CodeInput {
    CodeInput {
        target: "test-device".into(),
        action,
        project: Some(project.to_string_lossy().into()),
        tool: tool.map(str::to_owned),
        arguments: arguments.map(|v| v.as_object().unwrap().clone()),
        timeout: Some(300000),
    }
}
async fn call(manager: &Manager, project: &Path, tool: &str, arguments: Value) -> Result<Value> {
    let result = manager
        .execute(
            input(project, CodeAction::Call, Some(tool), Some(arguments)),
            CancellationToken::new(),
        )
        .await;
    println!("{tool}: {}", serde_json::to_string(&result)?);
    ensure!(
        !result.is_error(),
        "{tool} failed: {}",
        serde_json::to_string(&result)?
    );
    Ok(result.result.unwrap())
}
#[tokio::test]
#[ignore = "explicit real-backend test; provisions pinned tools in isolated test state"]
async fn real_project_lookup_edit_reuse_and_isolation() -> Result<()> {
    let root = std::env::var_os("WF_CODE_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "wayfinder-code-real-{}",
                wayfinder_core::random_secret()
            ))
        });
    if root.exists() {
        ensure!(
            root.join("integration-test-only").is_file(),
            "Refusing a non-test data directory"
        );
    }
    fs::create_dir_all(&root)?;
    fs::write(
        root.join("integration-test-only"),
        "Wayfinder explicit integration fixture",
    )?;
    let project = root.join("worktrees/a/project");
    let other = root.join("worktrees/b/project");
    fs::create_dir_all(project.join(".serena"))?;
    fs::create_dir_all(&other)?;
    fs::write(project.join(".serena/project.yml"), "malformed: [\n")?;
    fs::write(
        project.join("app.py"),
        "def total(a: int, b: int) -> int:\n    return a + b\n",
    )?;
    fs::write(
        project.join("consumer.py"),
        "from app import total\n\ndef use() -> int:\n    return total(2, 3)\n",
    )?;
    fs::write(
        other.join("app.py"),
        "def other() -> str:\n    return 'separate project'\n",
    )?;
    // Test the committed baseline, independent of future channel publications.
    wayfinder_code::Settings::set_automatic_updates(&root, false)?;
    let manager = Manager::new(&root);
    let outcome: Result<()> = async {
        let tools=manager.execute(input(&project,CodeAction::Tools,None,None),CancellationToken::new()).await;
        ensure!(!tools.is_error(), "Tool discovery failed: {}",serde_json::to_string(&tools)?);
        let tools=tools.result.unwrap();
        println!("tools: {}",serde_json::to_string(&tools["tools"].as_array().unwrap().iter().map(|t|t["name"].clone()).collect::<Vec<_>>())?);
        ensure!(tools["tools"].as_array().unwrap().iter().all(|t|t["name"].as_str().unwrap().starts_with("code_")&&!matches!(t["name"].as_str().unwrap(), "code_repl" | "code_serena_repl" | "code_execute_shell_command")), "Unexpected exposed tool");
        let pid=manager.status()?["projects"][0]["pid"].clone();
        call(&manager,&project,"code_find_symbol",json!({"name_path_pattern":"total","relative_path":"app.py","include_body":true})).await?;
        call(&manager,&project,"code_find_referencing_symbols",json!({"name_path":"total","relative_path":"app.py"})).await?;
        call(&manager,&project,"code_rename_symbol",json!({"name_path":"total","relative_path":"app.py","new_name":"sum_values"})).await?;
        ensure!(fs::read_to_string(project.join("consumer.py"))?.contains("sum_values(2, 3)"), "Cross-file rename did not update the caller");
        call(&manager,&project,"code_replace_symbol_body",json!({"name_path":"sum_values","relative_path":"app.py","body":"def sum_values(a: int, b: int) -> int:\n    return a + b + 1"})).await?;
        ensure!(fs::read_to_string(project.join("app.py"))?.contains("return a + b + 1"), "Symbol replacement was not applied");
        ensure!(manager.status()?["projects"][0]["pid"]==pid,"Project backend was not reused");
        let tools=manager.execute(input(&other,CodeAction::Tools,None,None),CancellationToken::new()).await;
        ensure!(!tools.is_error(),"Second project failed: {}",serde_json::to_string(&tools)?);
        call(&manager,&other,"code_find_symbol",json!({"name_path_pattern":"other","relative_path":"app.py","include_body":true})).await?;
        ensure!(manager.status()?["projects"].as_array().unwrap().len()==2,"Project sessions were not isolated");
        ensure!(fs::read_to_string(project.join(".serena/project.yml"))?=="malformed: [\n", "Repository backend configuration was touched");
        let closed=manager.execute(input(&project,CodeAction::Close,None,None),CancellationToken::new()).await;
        ensure!(!closed.is_error(),"Close failed");
        let typescript = root.join("worktrees/typescript");
        fs::create_dir_all(&typescript)?;
        fs::write(typescript.join("tsconfig.json"), r#"{"compilerOptions":{"strict":true},"include":["*.ts"]}"#)?;
        fs::write(typescript.join("app.ts"), "export function total(a: number, b: number): number { return a + b; }\n")?;
        fs::write(typescript.join("consumer.ts"), "import { total } from './app';\nexport const result = total(2, 3);\n")?;
        let tools = manager.execute(input(&typescript, CodeAction::Tools, None, None), CancellationToken::new()).await;
        ensure!(!tools.is_error(), "TypeScript setup failed: {}", serde_json::to_string(&tools)?);
        call(&manager, &typescript, "code_find_symbol", json!({"name_path_pattern":"total","relative_path":"app.ts","include_body":true})).await?;
        call(&manager, &typescript, "code_rename_symbol", json!({"name_path":"total","relative_path":"app.ts","new_name":"sumValues"})).await?;
        ensure!(fs::read_to_string(typescript.join("consumer.ts"))?.contains("sumValues(2, 3)"), "TypeScript cross-file rename did not update the caller");
        ensure!(!typescript.join("node_modules").exists() && !typescript.join(".serena").exists(), "Runtime dependencies leaked into the repository");
        println!("PASS: Python and TypeScript lookups and cross-file edits, managed Node.js/npm, process reuse, project isolation and private configuration");
        Ok(())
    }.await;
    manager.shutdown().await;
    outcome
}
