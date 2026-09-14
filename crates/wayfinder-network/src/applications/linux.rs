use anyhow::{Context, Result, ensure};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{fs::File, path::PathBuf};
use tokio::net::{UnixListener, UnixStream};

/// Machine-wide contract; an explicit XDG runtime isolates source-development instances.
pub fn socket_path() -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run"));
    ensure!(runtime.is_absolute(), "Runtime directory must be absolute");
    Ok(runtime.join("wayfinder/app.sock"))
}
pub struct Endpoint {
    listener: UnixListener,
    path: PathBuf,
    _lock: File,
}
impl Endpoint {
    pub fn bind() -> Result<Self> {
        let path = socket_path()?;
        let dir = path.parent().context("Missing runtime directory")?;
        let uid = std::fs::metadata("/proc/self")?.uid();
        let runtime = dir.parent().context("Missing runtime parent")?;
        if !runtime.exists() {
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
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let metadata = std::fs::symlink_metadata(dir)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o027 == 0,
            "Application directory must be daemon-owned, not group-writable and inaccessible to others"
        );
        // Only the daemon can change directory entries. The setgid bit makes the
        // socket inherit the provisioned application group, independent of umask.
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
