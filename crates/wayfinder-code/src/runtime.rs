use crate::{
    archive,
    channel::{self, Artifact, Pins},
    process, updates,
};
use anyhow::{Context, Result, ensure};
use process_wrap::tokio::CommandWrap;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;
use wayfinder_core::{atomic_write, digest, private_dir, read_private};

const DOWNLOAD_LIMIT: usize = 64 * 1024 * 1024;

pub fn recipe(root: &Path) -> Result<String> {
    Ok(updates::active(root)?.id())
}
pub fn root(data: &Path) -> PathBuf {
    data.join("code-intelligence")
}
fn recipe_dir(root: &Path, pins: &Pins) -> PathBuf {
    root.join("runtimes").join(pins.id())
}
fn python_path(directory: &Path) -> PathBuf {
    directory.join("environment").join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    })
}

pub fn lock(path: &Path, shared: bool) -> Result<File> {
    private_dir(path.parent().context("Missing lock parent")?)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let acquired = if shared {
        fs2::FileExt::try_lock_shared(&file)
    } else {
        fs2::FileExt::try_lock_exclusive(&file)
    };
    // fs2 returns ERROR_LOCK_VIOLATION on Windows, not std's WouldBlock kind.
    acquired.map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, error)
        } else {
            error
        }
    })?;
    Ok(file)
}

pub(crate) async fn installation_lock(root: &Path) -> Result<File> {
    loop {
        match lock(&root.join("install.lock"), false) {
            Ok(file) => return Ok(file),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.context("Code runtime installation lock unavailable")),
        }
    }
}
fn node_binary(directory: &Path) -> Result<PathBuf> {
    archive::find_file(
        &directory.join("node"),
        if cfg!(windows) {
            "node.exe"
        } else {
            "bin/node"
        },
    )
}
pub fn installed(root: &Path) -> bool {
    updates::active(root).is_ok_and(|pins| installed_pins(root, &pins))
}
pub(crate) fn installed_pins(root: &Path, pins: &Pins) -> bool {
    let directory = recipe_dir(root, pins);
    read_private::<Value>(&directory.join("ready.json"))
        .is_ok_and(|receipt| receipt["recipe"] == pins.id())
        && python_path(&directory).is_file()
        && node_binary(&directory).is_ok()
}

pub struct Runtime {
    pub python: PathBuf,
    pub recipe: String,
    uv: PathBuf,
    root: PathBuf,
    /// Deletion cannot race a running backend or a second CLI invocation.
    _lease: File,
}
impl Runtime {
    pub async fn ensure(root: &Path) -> Result<Self> {
        private_dir(root)?;
        let _install = installation_lock(root).await?;
        let settings =
            crate::Settings::load(root.parent().context("Missing code runtime parent")?)?;
        ensure!(settings.enabled, "Code intelligence is disabled");
        if settings.automatic_updates {
            updates::refresh_locked(root, false, false).await?;
        }
        Self::prepare_locked(root, &updates::active(root)?).await
    }
    /// Caller owns install.lock. Installation/qualification never recursively checks the channel.
    pub(crate) async fn prepare_locked(root: &Path, pins: &Pins) -> Result<Self> {
        pins.validate()?;
        let directory = recipe_dir(root, pins);
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let uv_pin = pins
            .uv
            .get(&platform)
            .context("Code intelligence is not available for this OS/architecture")?;
        if !installed_pins(root, pins) {
            let _exclusive = lock(&root.join("use.lock"), false)
                .context("Code runtime is in use; close code sessions before repairing it")?;
            if directory.exists() {
                fs::remove_dir_all(&directory)
                    .context("Cannot remove an incomplete private runtime")?;
            }
            private_dir(&directory)?;
            let result = Self::install(root, &directory, pins, uv_pin).await;
            if let Err(error) = result {
                atomic_write(
                    &root.join("setup-error.json"),
                    &json!({"error":format!("{error:#}")}),
                )?;
                return Err(anyhow::anyhow!(
                    "Wayfinder code runtime setup failed. Details: {}",
                    root.join("setup-error.json").display()
                ));
            }
        }
        let uv = archive::find_file(
            &directory.join("bootstrap"),
            if cfg!(windows) { "uv.exe" } else { "uv" },
        )?;
        Ok(Self {
            python: python_path(&directory),
            recipe: pins.id(),
            uv,
            root: root.to_owned(),
            _lease: lock(&root.join("use.lock"), true)?,
        })
    }
    async fn install(root: &Path, directory: &Path, pins: &Pins, uv_pin: &Artifact) -> Result<()> {
        let uv_bytes = download(root, uv_pin).await?;
        archive::extract(&uv_bytes, cfg!(windows), &directory.join("bootstrap"))?;
        let uv = archive::find_file(
            &directory.join("bootstrap"),
            if cfg!(windows) { "uv.exe" } else { "uv" },
        )?;
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let node_pin = pins
            .node
            .get(&platform)
            .context("Missing private Node.js runtime for this platform")?;
        let node = download(root, node_pin).await?;
        archive::extract(&node, cfg!(windows), &directory.join("node"))?;
        let mut verify_node = process::managed(Command::new(node_binary(directory)?));
        verify_node.command_mut().arg("--version");
        ensure!(
            process::run(verify_node).await?.trim() == pins.node_version,
            "Private Node.js runtime version mismatch"
        );
        let source = download(root, &pins.source).await?;
        archive::extract(&source, false, &directory.join("source"))?;
        let project = archive::find_file(&directory.join("source"), "pyproject.toml")?
            .parent()
            .expect("source parent")
            .to_owned();
        ensure!(
            project.join("uv.lock").is_file(),
            "Pinned source has no dependency lock"
        );
        let mut command = process::managed(Command::new(&uv));
        environment(command.command_mut(), root, directory, &uv)?;
        command
            .command_mut()
            .args([
                "--no-config",
                "sync",
                "--frozen",
                "--no-dev",
                "--no-default-groups",
                "--no-editable",
                "--managed-python",
                "--python",
                &pins.python,
                "--project",
            ])
            .arg(&project)
            .current_dir(directory);
        process::run(command)
            .await
            .context("Frozen dependency installation failed")?;
        let mut verify = process::managed(Command::new(python_path(directory)));
        environment(verify.command_mut(), root, directory, &uv)?;
        verify.command_mut().args(["-I", "-c", "import importlib.metadata as m,sys; assert '.'.join(map(str,sys.version_info[:3])) == sys.argv[1]; assert m.version('serena-agent') == sys.argv[2]; import serena.mcp", &pins.python, &pins.package_version]).current_dir(directory);
        process::run(verify)
            .await
            .context("Installed runtime verification failed")?;
        // Venv paths never move. This is installation readiness, not update activation.
        atomic_write(
            &directory.join("ready.json"),
            &json!({"schema":1,"recipe":pins.id(),"revision":pins.revision,"source_sha256":pins.source.sha256,"uv_version":pins.uv_version,"uv_sha256":uv_pin.sha256,"python":pins.python,"node_version":pins.node_version,"node_sha256":node_pin.sha256}),
        )?;
        let _ = fs::remove_file(root.join("setup-error.json"));
        Ok(())
    }
    pub fn command(&self) -> Result<CommandWrap> {
        let mut command = process::managed(Command::new(&self.python));
        let directory = self
            .python
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .context("Invalid runtime path")?;
        environment(command.command_mut(), &self.root, directory, &self.uv)?;
        Ok(command)
    }
}

fn environment(command: &mut Command, root: &Path, directory: &Path, uv: &Path) -> Result<()> {
    command
        .env("UV_CACHE_DIR", root.join("cache"))
        .env("UV_PYTHON_INSTALL_DIR", root.join("python"))
        .env("UV_PROJECT_ENVIRONMENT", directory.join("environment"))
        .env("UV_NO_PROGRESS", "1")
        .env("UV_NO_CONFIG", "1")
        .env("UV_MANAGED_PYTHON", "1");
    let mut paths = vec![
        python_path(directory)
            .parent()
            .expect("python parent")
            .to_owned(),
        uv.parent().expect("uv parent").to_owned(),
        node_binary(directory)?
            .parent()
            .expect("node parent")
            .to_owned(),
    ];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    command
        .env("PATH", std::env::join_paths(paths)?)
        .env("NPM_CONFIG_CACHE", root.join("cache/npm"))
        .env("NPM_CONFIG_UPDATE_NOTIFIER", "false")
        .env("NPM_CONFIG_FUND", "false")
        .env("NPM_CONFIG_AUDIT", "false");
    Ok(())
}
async fn download(root: &Path, artifact: &Artifact) -> Result<Vec<u8>> {
    ensure!(
        channel::hex_id(&artifact.sha256, 64),
        "Invalid artifact pin"
    );
    let downloads = root.join("downloads");
    private_dir(&downloads)?;
    let path = downloads.join(&artifact.sha256);
    if path.is_file() && fs::metadata(&path)?.len() <= DOWNLOAD_LIMIT as u64 {
        let bytes = fs::read(&path)?;
        if digest(&bytes) == artifact.sha256 {
            return Ok(bytes);
        }
        fs::remove_file(&path)?;
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() < 5
                && attempt.url().scheme() == "https"
                && matches!(
                    attempt.url().host_str(),
                    Some(
                        "nodejs.org"
                            | "github.com"
                            | "codeload.github.com"
                            | "release-assets.githubusercontent.com"
                            | "objects.githubusercontent.com"
                    )
                )
            {
                attempt.follow()
            } else {
                attempt.error("Unapproved artifact redirect")
            }
        }))
        .build()?;
    let mut response = client
        .get(&artifact.url)
        .header("User-Agent", "Wayfinder-code-runtime")
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= DOWNLOAD_LIMIT as u64),
        "Runtime download exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= DOWNLOAD_LIMIT,
            "Runtime download exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(
        digest(&bytes) == artifact.sha256,
        "Runtime artifact SHA-256 mismatch; nothing was executed"
    );
    let temporary = downloads.join(format!("{}.tmp", wayfinder_core::random_secret()));
    fs::write(&temporary, &bytes)?;
    fs::rename(temporary, &path)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipe_covers_supported_platforms_and_exact_sources() {
        let pins = channel::embedded();
        pins.validate().unwrap();
        assert_eq!(pins.schema, 1);
        assert_eq!(pins.revision.len(), 40);
        assert!(pins.source.url.ends_with(&pins.revision));
    }
    #[test]
    fn incomplete_runtime_is_never_ready() {
        let root = std::env::temp_dir().join(format!(
            "wayfinder-runtime-{}",
            wayfinder_core::random_secret()
        ));
        private_dir(&recipe_dir(&root, &channel::embedded())).unwrap();
        assert!(!installed(&root));
        fs::remove_dir_all(root).unwrap();
    }
}
