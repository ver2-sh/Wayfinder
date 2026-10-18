//! Run real upstream MCP against disposable files before changing the active pointer.
use crate::{
    backend::Backend,
    channel::{self, Pins},
    runtime::Runtime,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};
use wayfinder_core::{atomic_write, code::TOOLS, private_dir, read_private};

pub(crate) async fn qualify(root: &Path, pins: Pins) -> Result<()> {
    let runtime = Runtime::prepare_locked(root, &pins).await?;
    let directory = root.join("runtimes").join(pins.id());
    let receipt = directory.join("qualified.json");
    let probe = root.join("update-probe");
    // Also clear a probe left by cancellation before reusing a cached qualification.
    remove_probe(&probe).await?;
    if read_private::<Value>(&receipt)
        .is_ok_and(|v| v["integration"] == channel::INTEGRATION && v["recipe"] == pins.id())
    {
        return Ok(());
    }
    private_dir(&probe)?;
    let project = probe.join("fixture");
    private_dir(&project)?;
    fs::write(
        project.join("sample.py"),
        "def qualification_total(a: int, b: int) -> int:\n    return a + b\n",
    )?;
    fs::write(
        project.join("caller.py"),
        "from sample import qualification_total\n\nresult = qualification_total(2, 3)\n",
    )?;
    let result: Result<()> = async {
        let backend=Backend::start(&probe,&project,runtime).await?;
        let outcome:Result<()>=async {
            ensure!(TOOLS.iter().all(|name|backend.tools.iter().any(|t|t.name==format!("code_{name}"))),
                "Updated backend is missing required code tools");
            ensure!(backend.tools.iter().all(|t|t.input_schema.get("type")==Some(&json!("object"))),
                "Updated backend exposes incompatible tool schemas");
            let symbol=call(&backend,"find_symbol",json!({"name_path_pattern":"qualification_total","relative_path":"sample.py","include_body":true})).await?;
            ensure!(symbol.to_string().contains("return a + b"),"Updated backend could not resolve the qualification symbol");
            let refs=call(&backend,"find_referencing_symbols",json!({"name_path":"qualification_total","relative_path":"sample.py"})).await?;
            ensure!(refs.to_string().contains("caller.py"),"Updated backend could not resolve references");
            call(&backend,"rename_symbol",json!({"name_path":"qualification_total","relative_path":"sample.py","new_name":"qualified_total"})).await?;
            ensure!(fs::read_to_string(project.join("caller.py"))?.contains("qualified_total(2, 3)"),"Updated backend failed cross-file rename");
            call(&backend,"replace_symbol_body",json!({"name_path":"qualified_total","relative_path":"sample.py","body":"def qualified_total(a: int, b: int) -> int:\n    return a + b + 1"})).await?;
            ensure!(fs::read_to_string(project.join("sample.py"))?.contains("return a + b + 1"),"Updated backend failed symbol editing");
            Ok(())
        }.await;
        backend.stop().await;
        outcome
    }.await;
    let cleanup = remove_probe(&probe).await;
    result?;
    cleanup?;
    atomic_write(
        &receipt,
        &json!({"integration":channel::INTEGRATION,"recipe":pins.id(),"qualified_at":wayfinder_core::now()}),
    )?;
    Ok(())
}
async fn remove_probe(path: &Path) -> Result<()> {
    for attempt in 0..=20 {
        match fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            // Job termination can precede Windows releasing descendant file/directory handles.
            Err(error)
                if cfg!(windows)
                    && attempt < 20
                    && (matches!(
                        error.kind(),
                        std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::DirectoryNotEmpty
                    ) || matches!(error.raw_os_error(), Some(32 | 33))) =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => {
                return Err(error)
                    .context("Cannot remove disposable code runtime qualification files");
            }
        }
    }
    unreachable!("final cleanup attempt returns its result")
}

async fn call(backend: &Backend, name: &str, args: Value) -> Result<Value> {
    let result = backend
        .call(name, args.as_object().expect("fixture arguments").clone())
        .await?;
    ensure!(
        result["isError"] != true,
        "Updated backend rejected the qualification operation {name}"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "explicit qualification test; downloads pinned tools and runs real MCP in disposable files"]
    async fn real_qualification_is_private_and_preserves_active_selection() -> Result<()> {
        let data = std::env::var_os("WF_CODE_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "wayfinder-code-qualification-{}",
                    wayfinder_core::random_secret()
                ))
            });
        if data.exists() {
            ensure!(
                data.join("integration-test-only").is_file(),
                "Refusing a non-test directory"
            );
        }
        private_dir(&data)?;
        fs::write(
            data.join("integration-test-only"),
            "Wayfinder explicit integration fixture",
        )?;
        crate::Settings::set_automatic_updates(&data, false)?;
        let root = crate::runtime::root(&data);
        let selected = crate::updates::active(&root)?;
        let sentinel = data.join("user-file.txt");
        fs::write(&sentinel, "must not be changed by qualification")?;
        let _install = crate::runtime::installation_lock(&root).await?;
        // Test-only manifest input lets maintainers qualify a channel release without changing app pins.
        let pins = match std::env::var_os("WF_CODE_QUALIFICATION_MANIFEST") {
            Some(file) => channel::Manifest::decode(&fs::read(file)?)?.pins,
            None => channel::embedded(),
        };
        // Always execute the qualification in this opt-in test; reuse downloads, not the result.
        let qualification_receipt = root.join("runtimes").join(pins.id()).join("qualified.json");
        if qualification_receipt.exists() {
            fs::remove_file(qualification_receipt)?;
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(240),
            qualify(&root, pins.clone()),
        )
        .await??;
        let receipt: Value =
            read_private(&root.join("runtimes").join(pins.id()).join("qualified.json"))?;
        ensure!(
            receipt["integration"] == channel::INTEGRATION,
            "Qualification receipt missing"
        );
        ensure!(
            crate::updates::active(&root)? == selected,
            "Qualification changed the active pointer"
        );
        ensure!(
            !root.join("update-probe").exists(),
            "Qualification scratch data was not removed"
        );
        ensure!(
            fs::read_to_string(&sentinel)? == "must not be changed by qualification",
            "Qualification touched user files"
        );
        println!(
            "PASS: real upstream MCP qualification, symbols, references, cross-file rename, symbol edit, scratch cleanup and unchanged active selection"
        );
        Ok(())
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn probe_cleanup_waits_for_windows_file_handles() {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = std::env::temp_dir().join(format!(
            "wayfinder-probe-{}",
            wayfinder_core::random_secret()
        ));
        fs::create_dir_all(&directory).unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(directory.join("locked.txt"))
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(file);
        });
        let result = remove_probe(&directory).await;
        release.join().unwrap();
        result.unwrap();
        assert!(!directory.exists());
        remove_probe(&directory).await.unwrap();
    }
}
