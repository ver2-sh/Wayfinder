pub mod applications;

use anyhow::{Result, ensure};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;
use wayfinder_core::{identity::*, protocol::*, *};
pub(crate) type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
async fn send(s: &mut Socket, f: &Frame) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(10),
        s.send(Message::Text(serde_json::to_string(f)?.into())),
    )
    .await??;
    Ok(())
}
async fn receive(s: &mut Socket) -> Result<Frame> {
    loop {
        match s.next().await {
            Some(Ok(Message::Text(t))) => {
                ensure!(t.len() <= 131072, "Frame too large");
                return Ok(serde_json::from_str(&t)?);
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => anyhow::bail!("Gateway disconnected"),
        }
    }
}
/// Connect and authenticate one gateway WebSocket on `path` (`agent` for the
/// control session, `service` for a generic application relay stream). The
/// handshake is identical on both; the path only selects the gateway role.
pub(crate) async fn connect_path(i: &Installation, path: &str) -> Result<Socket> {
    i.validate()?;
    let url = format!(
        "{}/{path}?chain_id={}",
        i.gateway
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1),
        i.certificate.chain_id
    );
    let (s, _) = tokio::time::timeout(Duration::from_secs(20), connect_async(url)).await??;
    let mut s = s;
    let Frame::Challenge {
        version,
        gateway,
        nonce,
    } = tokio::time::timeout(Duration::from_secs(15), receive(&mut s)).await??
    else {
        anyhow::bail!("Gateway did not challenge")
    };
    ensure!(
        version == SESSION_VERSION && gateway == i.gateway,
        "Gateway identity or protocol mismatch"
    );
    key_bytes(&nonce)?;
    let metadata = PlatformDescriptor {
        platform: match std::env::consts::OS {
            "windows" => "windows",
            "linux" => "linux",
            "macos" => "macos",
            _ => "other",
        }
        .into(),
        arch: std::env::consts::ARCH.into(),
    };
    let signature = sign(
        &i.key()?,
        &session_proof(&i.gateway, &nonce, &i.certificate, &metadata)?,
    );
    send(
        &mut s,
        &Frame::Authenticate {
            certificate: i.certificate.clone(),
            metadata,
            signature,
        },
    )
    .await?;
    ensure!(
        matches!(
            tokio::time::timeout(Duration::from_secs(15), receive(&mut s)).await??,
            Frame::Ready
        ),
        "Gateway rejected device"
    );
    Ok(s)
}
pub async fn connect(i: &Installation) -> Result<Socket> {
    connect_path(i, "agent").await
}
pub async fn register(i: &Installation) -> Result<()> {
    let mut s = connect(i).await?;
    s.close(None).await?;
    Ok(())
}
pub async fn operation(i: &Installation, op: Operation) -> Result<serde_json::Value> {
    i.validate()?;
    ensure!(
        matches!(&op, Operation::Devices) || i.certificate.role == Role::Admin,
        "Administrative device required"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let c: serde_json::Value = client
        .post(format!(
            "{}/device/challenge?chain_id={}",
            i.gateway, i.certificate.chain_id
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        c["version"] == 1 && c["gateway"] == i.gateway,
        "Gateway mismatch"
    );
    let nonce = c["nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing challenge"))?
        .to_string();
    ensure!(!nonce.is_empty() && nonce.len() <= 160, "Invalid challenge");
    let signature = sign(
        &i.key()?,
        &operation_proof(&i.gateway, &nonce, &i.certificate, &op)?,
    );
    Ok(client
        .post(format!("{}/device/operation", i.gateway))
        .json(&SignedOperation {
            certificate: i.certificate.clone(),
            nonce,
            operation: op,
            signature,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
fn status(path: &Path, i: &Installation, online: bool) -> Result<()> {
    atomic_write(
        &path.join("status.json"),
        &serde_json::json!({"chain_id":i.certificate.chain_id,"device_id":i.certificate.device_id,"name":i.certificate.name,"role":i.certificate.role,"gateway":i.gateway,"online":online,"observed":now()}),
    )
}
pub async fn run(path: &Path, i: &Installation, stop: CancellationToken) -> Result<()> {
    run_inner(path, i, stop, false).await
}

/// Run embedded in a terminal UI; connection status remains available in status.json.
pub async fn run_quiet(path: &Path, i: &Installation, stop: CancellationToken) -> Result<()> {
    run_inner(path, i, stop, true).await
}

async fn run_inner(
    path: &Path,
    i: &Installation,
    stop: CancellationToken,
    quiet: bool,
) -> Result<()> {
    i.validate()?;
    let mut backoff = 1u64;
    status(path, i, false)?;
    // The local application endpoint runs independently of gateway
    // connectivity: registration/status work offline and remote opens recover
    // as sessions reconnect.
    let apps = Arc::new(applications::Apps::new(Arc::new(i.clone())));
    let endpoint_stop = stop.child_token();
    let endpoint = {
        let apps = apps.clone();
        tokio::spawn(async move { apps.serve(endpoint_stop).await })
    };
    loop {
        let started = tokio::time::Instant::now();
        let result =
            tokio::select! {_=stop.cancelled()=>break,r=session(path,i,&apps,stop.clone())=>r};
        status(path, i, false)?;
        if stop.is_cancelled() {
            break;
        }
        if result.is_err() && !quiet {
            eprintln!("Gateway session unavailable; retrying with the same device identity");
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = 1;
        }
        // Bounded jitter without secret material or identity regeneration.
        let jitter = u64::from_str_radix(&random_secret()[..4], 16).unwrap() % 1000;
        tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(backoff*1000+jitter))=>{}}
        backoff = (backoff * 2).min(30);
    }
    let _ = endpoint.await;
    status(path, i, false)?;
    Ok(())
}
struct StopTasks(CancellationToken);
impl Drop for StopTasks {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// One finished unit of session work. Service admission reports an error only
/// while a `service_reject` is still meaningful at the gateway.
enum Work {
    Exec {
        id: String,
        result: ExecResult,
    },
    Service {
        id: String,
        result: Result<(), String>,
    },
}

async fn session(
    path: &Path,
    i: &Installation,
    apps: &Arc<applications::Apps>,
    stop: CancellationToken,
) -> Result<()> {
    let mut socket = connect(i).await?;
    status(path, i, true)?;
    let session = stop.child_token();
    let _cleanup = StopTasks(session.clone());
    {
        let apps = apps.clone();
        let roster_stop = session.child_token();
        tokio::spawn(async move { apps.refresh_roster(roster_stop).await });
    }
    let mut tasks = tokio::task::JoinSet::new();
    let mut cancels = HashMap::new();
    let mut services = 0usize;
    let mut last = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = tick.tick() => {
                ensure!(last.elapsed() < Duration::from_secs(45), "Gateway heartbeat expired");
                status(path, i, true)?;
            },
            completed = tasks.join_next(), if !tasks.is_empty() => {
                match completed.unwrap()? {
                    Work::Exec { id, result } => {
                        cancels.remove(&id);
                        send(&mut socket, &Frame::Result { id, result }).await?;
                    },
                    Work::Service { id, result } => {
                        services -= 1;
                        if let Err(error) = result {
                            send(&mut socket, &Frame::ServiceReject { id, error }).await?;
                        }
                    },
                }
            },
            frame = receive(&mut socket) => {
                last = tokio::time::Instant::now();
                match frame? {
                    Frame::Ping => send(&mut socket, &Frame::Pong).await?,
                    Frame::Cancel { id } => {
                        if let Some(cancel) = cancels.get(&id) { CancellationToken::cancel(cancel); }
                    },
                    Frame::Exec { id, input } => {
                        ensure!(!cancels.contains_key(&id), "Duplicate execution ID");
                        if tasks.len() >= 16 {
                            let result = ExecResult::failed(i.certificate.device_id.clone(), "Device execution capacity reached");
                            send(&mut socket, &Frame::Result { id, result }).await?;
                            continue;
                        }
                        let cancel = session.child_token();
                        cancels.insert(id.clone(), cancel.clone());
                        let target = i.certificate.device_id.clone();
                        tasks.spawn(async move {
                            let result = wayfinder_exec::execute(target, input, cancel).await;
                            Work::Exec { id, result }
                        });
                    },
                    Frame::ServiceRequest { version, id, source, service } => {
                        ensure!(version == SERVICE_VERSION, "Unsupported service transport version");
                        ensure!(valid_device_id(&source).is_ok() && source != i.certificate.device_id, "Invalid service source");
                        ensure!(valid_node_id(&id).is_ok(), "Invalid service stream ID");
                        if services >= 16 {
                            send(&mut socket, &Frame::ServiceReject { id, error: "Device service capacity reached".into() }).await?;
                            continue;
                        }
                        services += 1;
                        let apps = apps.clone();
                        let cancel = session.child_token();
                        tasks.spawn(async move {
                            let result = tokio::select! {
                                _ = cancel.cancelled() => Ok(()),
                                r = apps.inbound(id.clone(), source, service) => r,
                            };
                            Work::Service { id, result }
                        });
                    },
                    _ => anyhow::bail!("Unexpected gateway frame"),
                }
            }
        }
    }
    session.cancel();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Root authorization is generated locally. Only public state and a signature leave the device.
pub async fn admit(i: &Installation, root: &ed25519_dalek::SigningKey) -> Result<()> {
    ensure!(
        hex::encode(root.verifying_key().as_bytes()) == i.certificate.root_public,
        "Recovery phrase belongs to another chain"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let c: serde_json::Value = client
        .post(format!(
            "{}/device/challenge?chain_id={}",
            i.gateway, i.certificate.chain_id
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        c["version"] == 1 && c["gateway"] == i.gateway,
        "Gateway mismatch"
    );
    let nonce = c["nonce"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing challenge"))?
        .to_string();
    ensure!(!nonce.is_empty() && nonce.len() <= 160, "Invalid challenge");
    let signature = sign(
        root,
        &security::admission_proof(&i.certificate, &i.gateway, &nonce)?,
    );
    client
        .post(format!("{}/device/admit", i.gateway))
        .json(&security::Admission {
            certificate: i.certificate.clone(),
            nonce,
            signature,
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
