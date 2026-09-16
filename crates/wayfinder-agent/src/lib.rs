use anyhow::{Result, ensure};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, path::Path, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_util::sync::CancellationToken;
use wayfinder_core::{identity::*, protocol::*, *};
type Socket =
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
pub async fn connect(i: &Installation) -> Result<Socket> {
    i.validate()?;
    let url = format!(
        "{}/agent",
        i.gateway
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1)
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
        version == 1 && gateway == i.gateway,
        "Gateway identity or protocol mismatch"
    );
    key_bytes(&nonce)?;
    let signature = sign(
        &i.key()?,
        &session_proof(&i.gateway, &nonce, &i.certificate)?,
    );
    send(
        &mut s,
        &Frame::Authenticate {
            certificate: i.certificate.clone(),
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
pub async fn register(i: &Installation) -> Result<()> {
    let mut s = connect(i).await?;
    s.close(None).await?;
    Ok(())
}
pub async fn operation(i: &Installation, op: Operation) -> Result<serde_json::Value> {
    i.validate()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?;
    let c: serde_json::Value = client
        .post(format!("{}/device/challenge", i.gateway))
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
    i.validate()?;
    let mut backoff = 1u64;
    status(path, i, false)?;
    loop {
        let started = tokio::time::Instant::now();
        let result = tokio::select! {_=stop.cancelled()=>break,r=session(path,i,stop.clone())=>r};
        status(path, i, false)?;
        if stop.is_cancelled() {
            break;
        }
        if result.is_err() {
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
    status(path, i, false)?;
    Ok(())
}
struct StopTasks(CancellationToken);
impl Drop for StopTasks {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
async fn session(path: &Path, i: &Installation, stop: CancellationToken) -> Result<()> {
    let mut socket = connect(i).await?;
    status(path, i, true)?;
    let session = stop.child_token();
    let _cleanup = StopTasks(session.clone());
    let mut tasks = tokio::task::JoinSet::new();
    let mut cancels = HashMap::new();
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
                let (id, result) = completed.unwrap()?;
                cancels.remove(&id);
                send(&mut socket, &Frame::Result { id, result }).await?;
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
                            (id, result)
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
