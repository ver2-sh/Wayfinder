use anyhow::{Context, Result, ensure};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{fs::File, path::PathBuf};
use tokio::net::{UnixListener, UnixStream};

/// Effective UID of this daemon, derived the same way applications derive it.
fn uid() -> Result<u32> {
    Ok(std::fs::metadata("/proc/self")?.uid())
}

/// Candidate runtime directories for the `wayfinder/app.sock` endpoint, in
/// preference order. The first that exists (or can be created under an
/// explicit XDG runtime) and passes ownership checks is used.
///
/// 1. `$XDG_RUNTIME_DIR` — the native per-user location for `--user` services
///    and login sessions. Also used to isolate source-development instances.
/// 2. `/run/user/<euid>` — the same location derived from the effective UID,
///    so applications without the environment (system services) agree.
/// 3. `/run` — the published machine endpoint `/run/wayfinder/app.sock`,
///    usable when an installer provisions `/run/wayfinder` for this account
///    (e.g. systemd `RuntimeDirectory=wayfinder`) or the daemon runs as root.
fn runtimes() -> Vec<(PathBuf, bool)> {
    let mut out = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        && runtime.is_absolute()
    {
        out.push((runtime, true));
    }
    if let Ok(uid) = uid() {
        out.push((PathBuf::from(format!("/run/user/{uid}")), false));
    }
    out.push((PathBuf::from("/run"), false));
    out
}

pub struct Endpoint {
    listener: UnixListener,
    path: PathBuf,
    _lock: File,
}
impl Endpoint {
    /// Bind the first viable runtime candidate. Returns an error when none
    /// exists so the supervisor can retry once the runtime appears.
    pub fn bind() -> Result<Self> {
        let uid = uid()?;
        let mut errors = Vec::new();
        for (runtime, creatable) in runtimes() {
            match Self::bind_in(&runtime, creatable, uid) {
                Ok(endpoint) => return Ok(endpoint),
                Err(e) => {
                    errors.push(format!("{runtime:?}: {e:#}"));
                }
            }
        }
        anyhow::bail!(
            "No usable application runtime directory ({})",
            errors.join("; ")
        )
    }

    fn bind_in(runtime: &PathBuf, creatable: bool, uid: u32) -> Result<Self> {
        let dir = runtime.join("wayfinder");
        let path = dir.join("app.sock");
        if !runtime.exists() {
            ensure!(creatable, "runtime directory absent");
            std::fs::create_dir(runtime)?;
            std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o700))?;
        }
        let metadata = std::fs::symlink_metadata(runtime)?;
        ensure!(
            metadata.is_dir()
                && (metadata.uid() == uid || metadata.uid() == 0)
                && metadata.mode() & 0o022 == 0,
            "Runtime parent must be owned by root or the daemon and not writable by others"
        );
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let metadata = std::fs::symlink_metadata(&dir)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o027 == 0,
            "Application directory must be daemon-owned, not group-writable and inaccessible to others"
        );
        // Only the daemon can change directory entries. The setgid bit makes the
        // socket inherit a provisioned application group, independent of umask.
        let shared = metadata.mode() & 0o050 == 0o050;
        ensure!(
            !shared || metadata.mode() & 0o2000 != 0,
            "Shared application directory must have setgid enabled"
        );
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(dir.join("daemon.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("A daemon already owns this application endpoint")?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(if shared { 0o660 } else { 0o600 }),
        )?;
        Ok(Self {
            listener,
            path,
            _lock: lock,
        })
    }
}
impl Endpoint {
    pub async fn accept(&mut self) -> Result<(UnixStream, String)> {
        let (stream, _) = self.listener.accept().await?;
        // Socket write permissions admit effective UID and supplementary groups.
        let uid = stream.peer_cred()?.uid();
        Ok((stream, format!("{uid}:{}", wayfinder_core::random_secret())))
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
