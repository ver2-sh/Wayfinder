//! Generic private peer services. No application protocol is interpreted here.
use super::{Channel, Network, Request, Response};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use wayfinder_core::secret_eq;

pub const SERVICE_VERSION: u32 = 1;
pub const HEADER_LIMIT: usize = 16384;
const LEASE: Duration = Duration::from_secs(60);
const SETUP: Duration = Duration::from_secs(5);

pub(super) struct Registration {
    address: SocketAddr,
    credential: String,
    expires: Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    version: u32,
    credential: String,
    target: String,
    service: String,
}

/// One u32 big-endian length followed by UTF-8 JSON; never line delimited.
pub async fn read_json<T: DeserializeOwned>(stream: &mut TcpStream) -> Result<T> {
    let len = stream.read_u32().await? as usize;
    ensure!(
        (1..=HEADER_LIMIT).contains(&len),
        "Invalid service header length"
    );
    let mut data = vec![0; len];
    stream.read_exact(&mut data).await?;
    Ok(serde_json::from_slice(&data)?)
}
pub async fn write_json<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    ensure!(data.len() <= HEADER_LIMIT, "Service header too large");
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    Ok(())
}
fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 96
            && name.bytes().all(|b| b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b'_')),
        "Invalid service name"
    );
    Ok(())
}
impl Network {
    /// Renewal requires the original registration credential; takeover is never implicit.
    pub async fn register_service(
        &self,
        service: String,
        address: SocketAddr,
        credential: String,
    ) -> Result<()> {
        validate_name(&service)?;
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Service must use a loopback endpoint"
        );
        ensure!(
            credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
            "Service credential must be 256-bit hex"
        );
        let mut services = self.services.lock().await;
        services.retain(|_, entry| entry.expires > Instant::now());
        if let Some(entry) = services.get(&service) {
            ensure!(
                secret_eq(&credential, &entry.credential) && address == entry.address,
                "Service already registered by another instance"
            );
        } else {
            ensure!(services.len() < 32, "Service registration capacity reached");
        }
        services.insert(
            service,
            Registration {
                address,
                credential,
                expires: Instant::now() + LEASE,
            },
        );
        Ok(())
    }
    pub async fn unregister_service(&self, service: String, credential: String) -> Result<()> {
        let mut services = self.services.lock().await;
        if let Some(entry) = services.get(&service) {
            ensure!(
                secret_eq(&credential, &entry.credential),
                "Service registration credential mismatch"
            );
            services.remove(&service);
        }
        Ok(())
    }
    async fn connect_service(&self, source: &str, service: &str) -> Result<TcpStream> {
        validate_name(service)?;
        let (address, credential) = {
            let services = self.services.lock().await;
            let entry = services
                .get(service)
                .filter(|e| e.expires > Instant::now())
                .context("Service unavailable: not registered or lease expired")?;
            (entry.address, entry.credential.clone())
        };
        let mut stream = TcpStream::connect(address)
            .await
            .context("Registered service is not running")?;
        stream.set_nodelay(true)?;
        write_json(
            &mut stream,
            &serde_json::json!({
                "version": SERVICE_VERSION, "credential": credential,
                "source": source, "target": self.node.id, "service": service
            }),
        )
        .await?;
        // The service must accept the authenticated preface before any caller bytes.
        let reply: serde_json::Value = read_json(&mut stream).await?;
        ensure!(
            reply == serde_json::json!({"version": SERVICE_VERSION, "ready": true}),
            "Service rejected transport preface"
        );
        Ok(stream)
    }
    pub(super) async fn incoming_service(
        &self,
        mut channel: Channel,
        version: u32,
        head: String,
        target: String,
        service: String,
    ) {
        let admission = tokio::time::timeout(SETUP, async {
            let source = self.authorize(&channel.remote).await?;
            ensure!(
                version == SERVICE_VERSION,
                "Unsupported peer service protocol version"
            );
            ensure!(
                target == self.node.id,
                "Service target must be this exact node"
            );
            ensure!(
                self.membership()
                    .await
                    .head()
                    .context("Missing membership")?
                    .hash()?
                    == head,
                "Membership differs; synchronize before service dispatch"
            );
            let permit = self
                .service_slots
                .clone()
                .try_acquire_owned()
                .context("Service stream capacity reached")?;
            let stream = self.connect_service(&source.id, &service).await?;
            Ok::<_, anyhow::Error>((stream, permit))
        })
        .await;
        let (stream, _permit) = match admission {
            Ok(Ok(accepted)) => accepted,
            other => {
                let message = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "Service admission timed out".into(),
                };
                let _ = tokio::time::timeout(SETUP, channel.send(&Response::Error(message))).await;
                return;
            }
        };
        if !matches!(
            tokio::time::timeout(
                SETUP,
                channel.send(&Response::ServiceReady {
                    version: SERVICE_VERSION
                })
            )
            .await,
            Ok(Ok(()))
        ) {
            return;
        }
        tokio::select! { _ = self.shutdown.cancelled() => {}, _ = channel.bridge(stream) => {} }
    }
    async fn open_peer_service(&self, target: &str, service: &str) -> Result<Channel> {
        self.ensure_active().await?;
        validate_name(service)?;
        let membership = self.membership().await;
        let node = membership
            .nodes()
            .iter()
            .find(|n| n.id == target)
            .context("Unknown stable target node ID")?;
        ensure!(
            node.id != self.node.id,
            "Peer service target must be a remote node"
        );
        let mut channel = Channel::connect(node.endpoint, &node.noise_key, &self.identity)
            .await
            .context("Peer unavailable or authentication failed before service dispatch")?;
        let head = membership.head().context("Missing membership")?.hash()?;
        channel
            .send(&Request::Service {
                version: SERVICE_VERSION,
                head,
                target: target.into(),
                service: service.into(),
            })
            .await?;
        match channel.receive::<Response>().await? {
            Response::ServiceReady {
                version: SERVICE_VERSION,
            } => Ok(channel),
            Response::Error(e) => bail!("{e}"),
            _ => bail!("Unsupported or invalid peer service response"),
        }
    }
    /// Separate authenticated local byte-stream listener; never part of MCP.
    pub async fn serve_services(
        self: Arc<Self>,
        listener: TcpListener,
        credential: String,
    ) -> Result<()> {
        ensure!(
            listener.local_addr()?.ip().is_loopback(),
            "Service control must bind loopback"
        );
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let (mut local, _) = accepted?;
                    let Ok(permit) = self.service_slots.clone().try_acquire_owned() else {
                        // Bound rejection work along with admitted streams.
                        let _ = tokio::time::timeout(Duration::from_millis(100), write_json(&mut local, &serde_json::json!({"version": 1, "error": "Service stream capacity reached"}))).await;
                        continue;
                    };
                    let network = self.clone();
                    let credential = credential.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let setup = tokio::time::timeout(SETUP, async {
                            let open: Open = read_json(&mut local).await?;
                            ensure!(secret_eq(&open.credential, &credential), "Invalid local service credential");
                            ensure!(open.version == SERVICE_VERSION, "Unsupported service protocol version");
                            network.open_peer_service(&open.target, &open.service).await
                        }).await;
                        match setup {
                            Ok(Ok(channel)) => {
                                if !matches!(tokio::time::timeout(SETUP, write_json(&mut local, &serde_json::json!({"version": 1, "ready": true}))).await, Ok(Ok(()))) { return; }
                                tokio::select! { _ = network.shutdown.cancelled() => {}, _ = channel.bridge(local) => {} }
                            }
                            other => {
                                let message = match other { Ok(Err(e)) => e.to_string(), _ => "Service open timed out; no application bytes dispatched".into() };
                                let _ = tokio::time::timeout(SETUP, write_json(&mut local, &serde_json::json!({"version": 1, "error": message}))).await;
                            }
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}
