//! OS-local application sessions, independent of administration and MCP.
use crate::{Network, services::read_json};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinSet,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Endpoint, socket_path};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Endpoint;

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
    pub async fn serve_applications(self: Arc<Self>, mut endpoint: Endpoint) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = endpoint.accept() => {
                    let (stream, owner) = accepted?;
                    if tasks.len() >= 64 { continue; }
                    let network = self.clone();
                    tasks.spawn(async move {
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
    async fn application_session(
        &self,
        mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        owner: &str,
    ) -> Result<()> {
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

async fn write_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &serde_json::Value,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 128 * 1024, "Application reply too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
