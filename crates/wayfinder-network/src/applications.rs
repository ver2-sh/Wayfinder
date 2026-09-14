//! OS-local application sessions, independent of administration and MCP.
use crate::{Network, services::read_json};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{fs::File, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinSet,
};

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
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Status,
    RegisterService {
        service: String,
        address: std::net::SocketAddr,
        credential: String,
    },
    UnregisterService {
        service: String,
    },
    OpenService {
        target: String,
        service: String,
    },
}
impl Network {
    pub async fn serve_applications(self: Arc<Self>, endpoint: Endpoint) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = endpoint.listener.accept() => {
                    let (stream, _) = accepted?;
                    // Linux checks socket write permission against the connecting process's
                    // effective UID and supplementary groups. Do not reimplement group
                    // admission via race-prone /proc or account-database lookups.
                    let uid = stream.peer_cred()?.uid();
                    if tasks.len() >= 64 { continue; }
                    let network = self.clone();
                    tasks.spawn(async move {
                        let owner = format!("{uid}:{}", wayfinder_core::random_secret());
                        tokio::select! {
                            _ = network.shutdown.cancelled() => {},
                            _ = network.application_session(stream, &owner) => {},
                        }
                        network.remove_session(&owner).await;
                    });
                }
            }
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
    async fn application_session(&self, mut stream: UnixStream, owner: &str) -> Result<()> {
        loop {
            let op: Operation = read_json(&mut stream).await?;
            if let Operation::OpenService { target, service } = op {
                let permit = self.service_slots.clone().try_acquire_owned()?;
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.open_peer_service(&target, &service),
                )
                .await;
                match result {
                    Ok(Ok(channel)) => {
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            write_reply(&mut stream, &json!({"version":1,"ready":true})),
                        )
                        .await??;
                        let _permit = permit;
                        return channel.bridge(stream).await;
                    }
                    other => {
                        let error = match other {
                            Ok(Err(e)) => e.to_string(),
                            _ => "Service open timed out before application dispatch".into(),
                        };
                        tokio::time::timeout(
                            Duration::from_secs(5),
                            write_reply(&mut stream, &json!({"error":error})),
                        )
                        .await??;
                        return Ok(());
                    }
                }
            }
            let result: Result<serde_json::Value> = async {
                match op {
                    Operation::Status => {
                        let status = self.status().await;
                        Ok(json!({"nodes":status.nodes,"conflict":status.conflict}))
                    }
                    Operation::RegisterService {
                        service,
                        address,
                        credential,
                    } => {
                        self.register_service(service, address, credential, owner.into())
                            .await?;
                        Ok(json!({"version":1,"registered":true}))
                    }
                    Operation::UnregisterService { service } => {
                        self.unregister_service(service, owner.into()).await?;
                        Ok(json!({"unregistered":true}))
                    }
                    Operation::OpenService { .. } => unreachable!(),
                }
            }
            .await;
            let reply = match result {
                Ok(value) => json!({"value":value}),
                Err(e) => json!({"error":e.to_string()}),
            };
            tokio::time::timeout(Duration::from_secs(5), write_reply(&mut stream, &reply))
                .await??;
        }
    }
}

async fn write_reply(stream: &mut UnixStream, value: &serde_json::Value) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 128 * 1024, "Application reply too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
