//! OS-local application sessions and generic services, independent of
//! administration and MCP.
//!
//! A live local application connects to the deterministic endpoint, observes
//! sanitized chain status and registers loopback services keyed to its session.
//! Opening a service runs an exact-device stream through the Sync Chain
//! gateway; the gateway relays ciphertext only, because each stream is an
//! end-to-end authenticated Noise channel between the two agents.
mod transport;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::Endpoint;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::Endpoint;

#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", windows)))]
use unsupported::Endpoint;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use wayfinder_core::{identity::*, protocol::*, *};

const HEADER_LIMIT: usize = 16384;
const SETUP: Duration = Duration::from_secs(15);
const ROSTER_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    RegisterService {
        service: String,
        address: SocketAddr,
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

struct Registration {
    address: SocketAddr,
    credential: String,
    owner: String,
}

/// Live local application/service state for one daemon. Registrations are
/// session-owned memory only; nothing is persisted or replicated.
pub struct Apps {
    installation: Arc<Installation>,
    services: Mutex<BTreeMap<String, Registration>>,
    /// Most recent chain roster observed through the authenticated session.
    roster: Mutex<Option<Arc<Vec<Device>>>>,
    /// Bounded inbound service streams.
    service_slots: Semaphore,
    /// Bounded outbound opens.
    open_slots: Semaphore,
}

impl Apps {
    pub fn new(installation: Arc<Installation>) -> Self {
        Self {
            installation,
            services: Mutex::new(BTreeMap::new()),
            roster: Mutex::new(None),
            service_slots: Semaphore::new(32),
            open_slots: Semaphore::new(32),
        }
    }

    /// Serve the OS-native endpoint until `stop` is cancelled. Binding is
    /// retried so an endpoint that appears later (login runtime directory,
    /// provisioned machine directory) is picked up without a restart.
    pub async fn serve(self: &Arc<Self>, stop: CancellationToken) {
        let mut tasks = JoinSet::new();
        loop {
            let mut endpoint = match Endpoint::bind() {
                Ok(endpoint) => endpoint,
                Err(_) => {
                    if tokio::time::timeout(Duration::from_secs(15), stop.cancelled())
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    continue;
                }
            };
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = endpoint.accept() => {
                        let Ok((stream, owner)) = accepted else { break };
                        if tasks.len() >= 64 { continue; }
                        let apps = self.clone();
                        let session_stop = stop.child_token();
                        tasks.spawn(async move {
                            tokio::select! {
                                _ = session_stop.cancelled() => {},
                                _ = apps.session(stream, &owner) => {},
                            }
                            apps.remove_session(&owner);
                        });
                    }
                }
                if stop.is_cancelled() {
                    break;
                }
            }
            if stop.is_cancelled() {
                break;
            }
            // The endpoint disappeared; rebind after a pause.
            if tokio::time::timeout(Duration::from_secs(5), stop.cancelled())
                .await
                .is_ok()
            {
                break;
            }
        }
        while tasks.join_next().await.is_some() {}
    }

    /// Keep the chain roster fresh while the gateway session is live. Status
    /// answers from the cache, so local IPC never waits on the network.
    pub async fn refresh_roster(self: &Arc<Self>, stop: CancellationToken) {
        loop {
            if let Ok(value) = crate::operation(
                &self.installation,
                wayfinder_core::protocol::Operation::Devices,
            )
            .await
                && let Ok(devices) = serde_json::from_value::<Vec<Device>>(value)
            {
                *self.roster.lock().unwrap() = Some(Arc::new(devices));
            }
            if tokio::time::timeout(ROSTER_INTERVAL, stop.cancelled())
                .await
                .is_ok()
            {
                break;
            }
        }
    }

    /// Sanitized node list for local applications: bare stable IDs, names,
    /// locality and reachability only. Without a roster the local device is
    /// reported alone so identity observation still works offline.
    fn nodes(&self) -> Vec<serde_json::Value> {
        let own = &self.installation.certificate;
        let roster = self.roster.lock().unwrap().clone();
        let mut nodes: Vec<serde_json::Value> = match roster.as_deref() {
            Some(devices) if !devices.is_empty() => devices
                .iter()
                .map(|d| {
                    json!({
                        "id": bare_device_id(&d.id),
                        "name": d.name,
                        "local": d.id == own.device_id,
                        "reachable": d.online && !d.revoked,
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        if !nodes.iter().any(|n| n["local"] == true) {
            nodes.insert(
                0,
                json!({
                    "id": bare_device_id(&own.device_id),
                    "name": own.name,
                    "local": true,
                    "reachable": true,
                }),
            );
        }
        nodes
    }

    async fn register_service(
        &self,
        service: String,
        address: SocketAddr,
        credential: String,
        owner: String,
    ) -> Result<()> {
        valid_service_name(&service)?;
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Service must use a loopback endpoint"
        );
        ensure!(
            credential.len() == 64 && credential.bytes().all(|b| b.is_ascii_hexdigit()),
            "Service credential must be 256-bit hex"
        );
        let mut services = self.services.lock().unwrap();
        if let Some(entry) = services.get(&service) {
            ensure!(
                entry.owner == owner
                    && secret_eq(&credential, &entry.credential)
                    && address == entry.address,
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
                owner,
            },
        );
        Ok(())
    }

    async fn unregister_service(&self, service: String, owner: String) -> Result<()> {
        let mut services = self.services.lock().unwrap();
        if let Some(entry) = services.get(&service) {
            ensure!(
                entry.owner == owner,
                "Service registration credential mismatch"
            );
            services.remove(&service);
        }
        Ok(())
    }

    fn remove_session(&self, owner: &str) {
        self.services
            .lock()
            .unwrap()
            .retain(|_, registration| registration.owner != owner);
    }

    /// One sequential local IPC session. `open_service` is terminal: on
    /// success the socket becomes the application byte stream.
    async fn session<S: AsyncRead + AsyncWrite + Unpin + Send>(
        self: &Arc<Self>,
        mut stream: S,
        owner: &str,
    ) -> Result<()> {
        loop {
            let op: Request = read_json(&mut stream).await?;
            if let Request::OpenService { target, service } = op {
                let permit = self
                    .open_slots
                    .try_acquire()
                    .map_err(|_| anyhow::anyhow!("Service open capacity reached"))?;
                let opened = tokio::time::timeout(SETUP, async {
                    let target = full_device_id(&target)?;
                    ensure!(
                        target != self.installation.certificate.device_id,
                        "Service target must be a remote device"
                    );
                    valid_service_name(&service)?;
                    transport::open(&self.installation, &target, &service).await
                })
                .await;
                match opened {
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
                            Ok(Err(e)) => format!("{e:#}"),
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
                    Request::Status => Ok(json!({"nodes":self.nodes(),"conflict":false})),
                    Request::RegisterService {
                        service,
                        address,
                        credential,
                    } => {
                        self.register_service(service, address, credential, owner.into())
                            .await?;
                        Ok(json!({"version":SERVICE_VERSION,"registered":true}))
                    }
                    Request::UnregisterService { service } => {
                        self.unregister_service(service, owner.into()).await?;
                        Ok(json!({"unregistered":true}))
                    }
                    Request::OpenService { .. } => unreachable!(),
                }
            }
            .await;
            let reply = match result {
                Ok(value) => json!({"value":value}),
                Err(e) => json!({"error":format!("{e:#}")}),
            };
            tokio::time::timeout(Duration::from_secs(5), write_reply(&mut stream, &reply))
                .await??;
        }
    }

    /// Admit an inbound service stream announced by `Frame::ServiceRequest`.
    /// Returns `Err` only while a `service_reject` can still be sent — once the
    /// stream is accepted the opener observes channel EOF/errors instead.
    pub async fn inbound(
        self: &Arc<Self>,
        id: String,
        source: String,
        service: String,
    ) -> Result<(), String> {
        let (address, credential) = {
            let services = self.services.lock().unwrap();
            match services.get(&service) {
                Some(entry) => (entry.address, entry.credential.clone()),
                None => return Err(format!("Service unavailable: {service} not registered")),
            }
        };
        let permit = self
            .service_slots
            .try_acquire()
            .map_err(|_| "Service stream capacity reached".to_string())?;
        let work = async {
            let mut backend = TcpStream::connect(address)
                .await
                .context("Registered service is not running")?;
            backend.set_nodelay(true)?;
            write_json(
                &mut backend,
                &json!({
                    "version": SERVICE_VERSION, "credential": credential,
                    "source": bare_device_id(&source),
                    "target": bare_device_id(&self.installation.certificate.device_id),
                    "service": service,
                }),
            )
            .await?;
            // The service must accept the authenticated preface before any
            // caller bytes are forwarded.
            let reply: serde_json::Value = read_json(&mut backend).await?;
            ensure!(
                reply == json!({"version":SERVICE_VERSION,"ready":true}),
                "Service rejected transport preface"
            );
            let channel = transport::accept(&self.installation, &id, &source, &service).await?;
            Ok::<_, anyhow::Error>((backend, channel))
        };
        match tokio::time::timeout(SETUP + SETUP, work).await {
            Ok(Ok((backend, channel))) => {
                let _permit = permit;
                let _ = channel.bridge(backend).await;
                Ok(())
            }
            // Once paired the pending is gone at the gateway, so a late reject
            // is harmlessly dropped; the opener observes channel teardown.
            Ok(Err(e)) => Err(format!("{e:#}")),
            Err(_) => Err("Service admission timed out".into()),
        }
    }
}

async fn write_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &serde_json::Value,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 128 * 1024, "Application reply too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn read_json<T: serde::de::DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<T> {
    let len = stream.read_u32().await? as usize;
    ensure!(
        (1..=HEADER_LIMIT).contains(&len),
        "Invalid service header length"
    );
    let mut data = vec![0; len];
    stream.read_exact(&mut data).await?;
    Ok(serde_json::from_slice(&data)?)
}

async fn write_json<T: serde::Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    ensure!(data.len() <= HEADER_LIMIT, "Service header too large");
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(&data).await?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod e2e;

#[cfg(test)]
mod tests {
    use super::*;

    fn apps() -> Arc<Apps> {
        let root = new_key();
        let key = new_key();
        let certificate = Certificate::issue(&root, &key, "node".into(), Role::Admin).unwrap();
        let installation =
            Installation::new("http://127.0.0.1:1".into(), certificate, &key).unwrap();
        Arc::new(Apps::new(Arc::new(installation)))
    }

    #[tokio::test]
    async fn registrations_are_session_owned() {
        let apps = apps();
        let address: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let credential = "a".repeat(64);
        apps.register_service("echo.v1".into(), address, credential.clone(), "u:1".into())
            .await
            .unwrap();
        // Identical re-registration on the owning session is harmless.
        apps.register_service("echo.v1".into(), address, credential.clone(), "u:1".into())
            .await
            .unwrap();
        // Another session cannot take over, even with the credential.
        assert!(
            apps.register_service("echo.v1".into(), address, credential.clone(), "u:2".into())
                .await
                .is_err()
        );
        // Only the owner may unregister.
        assert!(
            apps.unregister_service("echo.v1".into(), "u:2".into())
                .await
                .is_err()
        );
        apps.unregister_service("echo.v1".into(), "u:1".into())
            .await
            .unwrap();
        // Session teardown removes all of its registrations.
        apps.register_service("gone.v1".into(), address, credential, "u:3".into())
            .await
            .unwrap();
        apps.remove_session("u:3");
        assert!(!apps.services.lock().unwrap().contains_key("gone.v1"));
    }

    #[tokio::test]
    async fn registrations_require_loopback_and_valid_names() {
        let apps = apps();
        let credential = "b".repeat(64);
        for address in ["8.8.8.8:53", "10.0.0.2:9000", "127.0.0.1:0"] {
            assert!(
                apps.register_service(
                    "ok.v1".into(),
                    address.parse().unwrap(),
                    credential.clone(),
                    "u:1".into()
                )
                .await
                .is_err()
            );
        }
        for name in ["", "UPPER", "has space", "wayfinder/..", &"x".repeat(97)] {
            assert!(
                apps.register_service(
                    name.into(),
                    "127.0.0.1:1".parse().unwrap(),
                    credential.clone(),
                    "u:1".into()
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn status_reports_local_identity_without_roster() {
        let apps = apps();
        let nodes = apps.nodes();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["local"], true);
        assert_eq!(nodes[0]["reachable"], true);
        assert_eq!(
            nodes[0]["id"].as_str().unwrap(),
            bare_device_id(&apps.installation.certificate.device_id)
        );
    }
}
