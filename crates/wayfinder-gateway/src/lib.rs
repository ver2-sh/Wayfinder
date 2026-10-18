use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use wayfinder_core::code::{
    CODE_SESSION_VERSION, CodeInput, CodeResult, DEFAULT_TIMEOUT, OUTPUT_LIMIT,
};
use wayfinder_core::{
    credentials::{ClientIdentity, CredentialStore},
    identity::{Certificate, Role, verify},
    protocol::*,
    *,
};
type Key = (String, String);
struct CodeDispatch {
    id: String,
    input: CodeInput,
    response: oneshot::Sender<CodeResult>,
    cancel: CancellationToken,
}
struct Dispatch {
    id: String,
    input: ExecInput,
    response: oneshot::Sender<ExecResult>,
    cancel: CancellationToken,
}
/// Work delivered to a live agent session: shell dispatch or a generic
/// service-stream request.
enum AgentEvent {
    Exec(Dispatch),
    Code(CodeDispatch),
    Service {
        id: String,
        source: String,
        service: String,
    },
}
/// One in-flight `service_open`: the opener's relay socket waits for the
/// target's relay socket to accept.
struct Pending {
    target: String,
    /// The opener's stream inbox; given to the accepter on pairing.
    opener: mpsc::Sender<Message>,
    /// Resolves to the accepter's inbox sender, or the rejection reason.
    notify: oneshot::Sender<Result<mpsc::Sender<Message>, String>>,
}
#[derive(Clone)]
struct Session {
    generation: String,
    code: bool,
    send: mpsc::Sender<AgentEvent>,
    stop: CancellationToken,
}
pub struct Gateway {
    pub issuer: String,
    pub store: Arc<CredentialStore>,
    oauth: Arc<oauth::OAuth>,
    sessions: Mutex<HashMap<Key, Session>>,
    challenge_key: String,
    nonces: Mutex<HashMap<Key, HashMap<String, u64>>>,
    handshakes: Arc<tokio::sync::Semaphore>,
    approvals: Mutex<HashMap<Key, (u64, u32)>>,
    administration: Mutex<()>,
    connections: Arc<tokio::sync::Semaphore>,
    /// Unpaired `service_open` requests, keyed by (chain, stream ID).
    pendings: Mutex<HashMap<Key, Pending>>,
    /// Live relay sockets per chain, bounded independently of agent sessions.
    relays: Mutex<HashMap<String, usize>>,
}
impl Gateway {
    pub fn new(issuer: String, store: Arc<CredentialStore>) -> Result<Arc<Self>> {
        identity::validate_gateway(&issuer)?;
        let oauth = Arc::new(oauth::OAuth::new(issuer.clone(), store.clone())?);
        Ok(Arc::new(Self {
            issuer,
            store,
            oauth,
            sessions: Mutex::new(HashMap::new()),
            challenge_key: random_secret(),
            nonces: Mutex::new(HashMap::new()),
            handshakes: Arc::new(tokio::sync::Semaphore::new(128)),
            approvals: Mutex::new(HashMap::new()),
            administration: Mutex::new(()),
            connections: Arc::new(tokio::sync::Semaphore::new(1024)),
            pendings: Mutex::new(HashMap::new()),
            relays: Mutex::new(HashMap::new()),
        }))
    }
    pub fn expire(&self) -> Result<()> {
        self.oauth.expire()?;
        self.nonces.lock().unwrap().retain(|_, used| {
            used.retain(|_, expiry| *expiry > now());
            !used.is_empty()
        });
        self.approvals
            .lock()
            .unwrap()
            .retain(|_, (t, _)| *t + 60 > now());
        Ok(())
    }
    pub fn router(self: &Arc<Self>) -> Router {
        let protocol = Router::new()
            .route("/agent", get(upgrade))
            .route("/service", get(service_upgrade))
            .route("/device/challenge", post(challenge))
            .route("/device/operation", post(operation))
            .route("/device/admit", post(admit))
            .layer(DefaultBodyLimit::max(131072))
            .with_state(self.clone());
        wayfinder_mcp::router(self.clone(), self.store.clone(), self.oauth.clone())
            .merge(protocol)
            .layer(axum::middleware::from_fn(edge_guard))
    }
    fn nodes(&self, chain: &str) -> Result<serde_json::Value> {
        let mut devices = self.store.devices(chain)?;
        let sessions = self.sessions.lock().unwrap();
        for d in &mut devices {
            d.online = !d.revoked
                && sessions
                    .get(&(chain.into(), d.id.clone()))
                    .is_some_and(|s| !s.stop.is_cancelled());
        }
        let mut value = serde_json::to_value(devices)?;
        if let Some(devices) = value.as_array_mut() {
            for device in devices {
                let supported = device["id"]
                    .as_str()
                    .and_then(|id| sessions.get(&(chain.to_owned(), id.to_owned())))
                    .is_some_and(|session| session.code && !session.stop.is_cancelled());
                device["code_intelligence"] = serde_json::Value::Bool(supported);
            }
        }
        Ok(value)
    }
    fn operate(&self, s: SignedOperation) -> Result<serde_json::Value> {
        let _administration = self.administration.lock().unwrap();
        let expiry = self.verify_challenge(&s.nonce)?;
        s.certificate.verify()?;
        verify(
            &s.certificate.device_public,
            &operation_proof(&self.issuer, &s.nonce, &s.certificate, &s.operation)?,
            &s.signature,
        )?;
        let c = &s.certificate;
        self.store.active(c)?;
        let key = (c.chain_id.clone(), c.device_id.clone());
        ensure!(
            self.sessions
                .lock()
                .unwrap()
                .get(&key)
                .is_some_and(|s| !s.stop.is_cancelled()),
            "Administrative device must be connected"
        );
        if !matches!(s.operation, Operation::Devices) {
            ensure!(c.role == Role::Admin, "Administrative device required");
        }
        // Only a verified, live device can allocate replay state. Keep it across
        // reconnects until expiry; clearing it on disconnect would permit replay.
        {
            let mut nonces = self.nonces.lock().unwrap();
            nonces.retain(|_, used| {
                used.retain(|_, expiry| *expiry > now());
                !used.is_empty()
            });
            let used = nonces.entry(key.clone()).or_default();
            ensure!(used.len() < 128, "Device operation rate limit");
            ensure!(!used.contains_key(&s.nonce), "Challenge already used");
            used.insert(s.nonce, expiry);
        }
        match s.operation {
            Operation::Devices => self.nodes(&c.chain_id),
            Operation::RevokeDevice { device_id } => {
                self.store.revoke_device(&c.chain_id, &device_id)?;
                if let Some(session) = self
                    .sessions
                    .lock()
                    .unwrap()
                    .remove(&(c.chain_id.clone(), device_id))
                {
                    session.stop.cancel();
                }
                Ok(serde_json::json!({"revoked":true}))
            }
            Operation::Pending { code } => {
                let mut limits = self.approvals.lock().unwrap();
                limits.retain(|_, (t, _)| *t + 60 > now());
                let limit = limits.entry(key).or_insert((now(), 0));
                ensure!(limit.1 < 10, "Approval lookup rate limit; wait one minute");
                limit.1 += 1;
                Ok(serde_json::to_value(self.oauth.pending(&code)?)?)
            }
            Operation::Approve { code, request_hash } => {
                self.oauth
                    .approve(&code, c.chain_id.clone(), &request_hash)?;
                Ok(serde_json::json!({"approved":true}))
            }
            Operation::Grants => Ok(serde_json::to_value(self.store.list(&c.chain_id)?)?),
            Operation::RevokeGrant { grant_id } => {
                self.store.revoke(&c.chain_id, &grant_id)?;
                Ok(serde_json::json!({"revoked":true}))
            }
        }
    }
    fn challenge(&self) -> String {
        let payload = format!("{}.{}", now() + 30, random_secret());
        let mut mac = Hmac::<Sha256>::new_from_slice(self.challenge_key.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()))
    }
    fn verify_challenge(&self, nonce: &str) -> Result<u64> {
        ensure!(nonce.len() <= 160, "Invalid challenge");
        let (payload, tag) = nonce
            .rsplit_once('.')
            .ok_or_else(|| anyhow::anyhow!("Invalid challenge"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(self.challenge_key.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        mac.verify_slice(&hex::decode(tag)?)?;
        let (expiry, _) = payload
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("Invalid challenge"))?;
        let expiry: u64 = expiry.parse()?;
        ensure!(expiry > now() && expiry <= now() + 30, "Expired challenge");
        Ok(expiry)
    }
    /// The shared WebSocket challenge/certificate authentication used by both
    /// `/agent` control sessions and `/service` relay sockets.
    async fn authenticate(
        &self,
        socket: &mut WebSocket,
        version: u32,
    ) -> Result<(Certificate, PlatformDescriptor)> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let nonce = random_secret();
            send(
                socket,
                &Frame::Challenge {
                    version,
                    gateway: self.issuer.clone(),
                    nonce: nonce.clone(),
                },
            )
            .await?;
            let frame = receive(socket).await?;
            let Frame::Authenticate {
                certificate,
                metadata,
                signature,
            } = frame
            else {
                anyhow::bail!("Authentication required")
            };
            certificate.verify()?;
            verify(
                &certificate.device_public,
                &session_proof_for(version, &self.issuer, &nonce, &certificate, &metadata)?,
                &signature,
            )?;
            Ok::<_, anyhow::Error>((certificate, metadata))
        })
        .await?
    }
    async fn connection(
        self: Arc<Self>,
        mut socket: WebSocket,
        handshake: tokio::sync::OwnedSemaphorePermit,
        version: u32,
    ) -> Result<()> {
        let (certificate, metadata) = self.authenticate(&mut socket, version).await?;
        drop(handshake);
        let _permit = self.connections.clone().try_acquire_owned()?;
        let key = (certificate.chain_id.clone(), certificate.device_id.clone());
        let generation = random_secret();
        let stop = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel::<AgentEvent>(16);
        {
            let _administration = self.administration.lock().unwrap();
            let sessions = self.sessions.lock().unwrap();
            ensure!(
                sessions.contains_key(&key)
                    || sessions
                        .keys()
                        .filter(|(chain, _)| chain == &certificate.chain_id)
                        .count()
                        < 64,
                "Chain connection capacity reached"
            );
            drop(sessions);
            self.store.register(&certificate, Some(&metadata))?;
            if let Some(old) = self.sessions.lock().unwrap().insert(
                key.clone(),
                Session {
                    generation: generation.clone(),
                    code: version == CODE_SESSION_VERSION,
                    send: tx,
                    stop: stop.clone(),
                },
            ) {
                old.stop.cancel();
            }
        }
        let outcome = self
            .connected(&mut socket, &certificate, &mut rx, &stop)
            .await;
        stop.cancel();
        let mut sessions = self.sessions.lock().unwrap();
        if sessions
            .get(&key)
            .is_some_and(|s| s.generation == generation)
        {
            sessions.remove(&key);
        }
        drop(sessions);
        // Unpaired opens aimed at this device can never complete once its
        // control session is gone.
        let dead: Vec<Key> = self
            .pendings
            .lock()
            .unwrap()
            .iter()
            .filter(|((chain, _), p)| {
                *chain == certificate.chain_id && p.target == certificate.device_id
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in dead {
            if let Some(p) = self.pendings.lock().unwrap().remove(&key) {
                let _ = p.notify.send(Err("Device disconnected".into()));
            }
        }
        outcome
    }
    async fn connected(
        &self,
        socket: &mut WebSocket,
        c: &Certificate,
        rx: &mut mpsc::Receiver<AgentEvent>,
        stop: &CancellationToken,
    ) -> Result<()> {
        send(socket, &Frame::Ready).await?;
        let mut pending: HashMap<String, (oneshot::Sender<ExecResult>, CancellationToken)> =
            HashMap::new();
        let mut code_pending: HashMap<String, (oneshot::Sender<CodeResult>, CancellationToken)> =
            HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut last = tokio::time::Instant::now();
        let mut heartbeat = 0;
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tick.tick() => {
                    ensure!(last.elapsed() < Duration::from_secs(45), "Heartbeat expired");
                    self.store.active(c)?;
                    heartbeat += 1;
                    if heartbeat % 15 == 0 { send(socket, &Frame::Ping).await?; }
                    let cancelled: Vec<_> = pending.iter()
                        .filter(|(_, (_, cancel))| cancel.is_cancelled())
                        .map(|(id, _)| id.clone()).collect();
                    for id in cancelled {
                        pending.remove(&id);
                        send(socket, &Frame::Cancel { id }).await?;
                    }
                    let cancelled: Vec<_> = code_pending.iter().filter(|(_, (_, cancel))| cancel.is_cancelled()).map(|(id, _)| id.clone()).collect();
                    for id in cancelled { code_pending.remove(&id); send(socket, &Frame::Cancel { id }).await?; }
                },
                event = rx.recv() => {
                    let Some(e) = event else { break };
                    self.store.active(c)?;
                    match e {
                        AgentEvent::Exec(d) => {
                            if d.cancel.is_cancelled() { continue; }
                            if pending.len() + code_pending.len() >= 64 { let _ = d.response.send(ExecResult::failed(c.device_id.clone(), "Execution capacity reached")); continue; }
                            send(socket, &Frame::Exec { id: d.id.clone(), input: d.input }).await?;
                            pending.insert(d.id, (d.response, d.cancel));
                        },
                        AgentEvent::Code(d) => {
                            if d.cancel.is_cancelled() { continue; }
                            if pending.len() + code_pending.len() >= 64 { let _ = d.response.send(CodeResult::failed(&d.input, "Execution capacity reached")); continue; }
                            send(socket, &Frame::Code { id: d.id.clone(), input: d.input }).await?;
                            code_pending.insert(d.id, (d.response, d.cancel));
                        },
                        AgentEvent::Service { id, source, service } => {
                            send(socket, &Frame::ServiceRequest { version: SERVICE_VERSION, id, source, service }).await?;
                        },
                    }
                },
                frame = receive(socket) => match frame? {
                    Frame::Pong => { last = tokio::time::Instant::now(); self.store.register(c, None)?; },
                    Frame::Result { id, result } => {
                        if let Some((tx, _)) = pending.remove(&id) { let _ = tx.send(result); }
                    },
                    Frame::CodeResult { id, mut result } => {
                        if let Some((tx, _)) = code_pending.remove(&id) {
                            if serde_json::to_vec(&result)?.len() > OUTPUT_LIMIT {
                                result.result = None; result.error = Some("Code result exceeds 1 MiB; inspect edits before repeating the operation".into()); result.outcome_unknown = true;
                            }
                            let _ = tx.send(result);
                        }
                    },
                    Frame::ServiceReject { id, error } => {
                        let key = (c.chain_id.clone(), id);
                        let mut pendings = self.pendings.lock().unwrap();
                        if pendings.get(&key).is_some_and(|p| p.target == c.device_id)
                            && let Some(p) = pendings.remove(&key)
                        {
                            let _ = p.notify.send(Err(error));
                        }
                    },
                    _ => anyhow::bail!("Unexpected frame"),
                }
            }
        }
        Ok(())
    }
    /// `/service` relay connection: authenticate, then pair one open with one
    /// accept and forward opaque records between them.
    async fn service_connection(
        self: Arc<Self>,
        mut socket: WebSocket,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<()> {
        let (certificate, _) = self.authenticate(&mut socket, SESSION_VERSION).await?;
        drop(handshake);
        let _permit = self.connections.clone().try_acquire_owned()?;
        self.store.active(&certificate)?;
        {
            let mut relays = self.relays.lock().unwrap();
            let count = relays.entry(certificate.chain_id.clone()).or_default();
            ensure!(*count < 128, "Chain service stream capacity reached");
            *count += 1;
        }
        let _guard = RelayGuard {
            gateway: self.clone(),
            chain: certificate.chain_id.clone(),
        };
        send(&mut socket, &Frame::Ready).await?;
        let frame = tokio::time::timeout(Duration::from_secs(10), receive(&mut socket)).await??;
        match frame {
            Frame::ServiceOpen {
                version,
                id,
                target,
                service,
            } => {
                self.open_relay(socket, &certificate, version, id, target, service)
                    .await
            }
            Frame::ServiceAccept { version, id } => {
                self.accept_relay(socket, &certificate, version, id).await
            }
            _ => anyhow::bail!("Relay socket requires an open or accept"),
        }
    }
    async fn open_relay(
        &self,
        mut socket: WebSocket,
        c: &Certificate,
        version: u32,
        id: String,
        target: String,
        service: String,
    ) -> Result<()> {
        if let Err(e) = (|| -> Result<()> {
            ensure!(
                version == SERVICE_VERSION,
                "Unsupported service transport version"
            );
            valid_node_id(&id)?;
            valid_device_id(&target)?;
            ensure!(
                target != c.device_id,
                "Service target must be a remote device"
            );
            valid_service_name(&service)?;
            Ok(())
        })() {
            service_fail(&mut socket, &id, format!("{e:#}")).await;
            return Ok(());
        }
        let key = (c.chain_id.clone(), id.clone());
        let (opener, inbox) = mpsc::channel::<Message>(64);
        let (notify, verdict) = oneshot::channel();
        {
            let mut pendings = self.pendings.lock().unwrap();
            ensure!(
                pendings
                    .keys()
                    .filter(|(chain, _)| chain == &c.chain_id)
                    .count()
                    < 32,
                "Chain pending service capacity reached"
            );
            ensure!(!pendings.contains_key(&key), "Duplicate service stream ID");
            pendings.insert(
                key.clone(),
                Pending {
                    target: target.clone(),
                    opener,
                    notify,
                },
            );
        }
        let admitted = (|| -> Result<()> {
            let session = self
                .sessions
                .lock()
                .unwrap()
                .get(&(c.chain_id.clone(), target.clone()))
                .cloned()
                .filter(|s| !s.stop.is_cancelled())
                .ok_or_else(|| anyhow::anyhow!("Target device offline"))?;
            session
                .send
                .try_send(AgentEvent::Service {
                    id: id.clone(),
                    source: c.device_id.clone(),
                    service,
                })
                .map_err(|_| anyhow::anyhow!("Target device busy"))
        })();
        if let Err(e) = admitted {
            self.pendings.lock().unwrap().remove(&key);
            service_fail(&mut socket, &id, format!("{e:#}")).await;
            return Ok(());
        }
        let pairing = tokio::select! {
            verdict = tokio::time::timeout(Duration::from_secs(15), verdict) => {
                match verdict {
                    Ok(Ok(Ok(peer))) => Ok(peer),
                    Ok(Ok(Err(e))) => Err(e),
                    _ => Err("Service open timed out before admission".into()),
                }
            },
            closed = socket.recv() => {
                self.pendings.lock().unwrap().remove(&key);
                let _ = closed;
                anyhow::bail!("Opener disconnected before pairing");
            }
        };
        let peer = match pairing {
            Ok(peer) => peer,
            Err(error) => {
                // The pending may already be gone (a service_reject removed it
                // to deliver this verdict); the opener still needs the error.
                self.pendings.lock().unwrap().remove(&key);
                service_fail(&mut socket, &id, error).await;
                return Ok(());
            }
        };
        send(&mut socket, &Frame::ServiceReady { id }).await?;
        self.relay(socket, inbox, peer).await
    }
    async fn accept_relay(
        &self,
        mut socket: WebSocket,
        c: &Certificate,
        version: u32,
        id: String,
    ) -> Result<()> {
        if let Err(e) = (|| -> Result<()> {
            ensure!(
                version == SERVICE_VERSION,
                "Unsupported service transport version"
            );
            valid_node_id(&id)?;
            Ok(())
        })() {
            service_fail(&mut socket, &id, format!("{e:#}")).await;
            return Ok(());
        }
        let key = (c.chain_id.clone(), id.clone());
        let pending = {
            let mut pendings = self.pendings.lock().unwrap();
            match pendings.get(&key) {
                Some(p) if p.target == c.device_id => pendings.remove(&key),
                _ => None,
            }
        };
        let Some(pending) = pending else {
            service_fail(&mut socket, &id, "Unknown or expired service stream".into()).await;
            return Ok(());
        };
        let (sender, inbox) = mpsc::channel::<Message>(64);
        if pending.notify.send(Ok(sender)).is_err() {
            service_fail(&mut socket, &id, "Service opener disconnected".into()).await;
            return Ok(());
        }
        send(&mut socket, &Frame::ServiceReady { id }).await?;
        self.relay(socket, inbox, pending.opener).await
    }
    /// Forward opaque records between this relay socket and the paired peer's
    /// inbox. Either side closing tears the stream down in both directions.
    async fn relay(
        &self,
        socket: WebSocket,
        mut inbox: mpsc::Receiver<Message>,
        peer: mpsc::Sender<Message>,
    ) -> Result<()> {
        let (mut sink, mut stream) = socket.split();
        let out = tokio::spawn(async move {
            while let Some(message) = inbox.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            sink
        });
        while let Some(message) = stream.next().await {
            match message {
                Ok(m @ (Message::Binary(_) | Message::Text(_))) => {
                    let size = match &m {
                        Message::Binary(b) => b.len(),
                        Message::Text(t) => t.len(),
                        _ => 0,
                    };
                    if size > 66000 || peer.send(m).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                _ => break,
            }
        }
        if let Ok(mut sink) = out.await {
            let _ = sink.close().await;
        }
        Ok(())
    }
}
async fn service_fail(socket: &mut WebSocket, id: &str, error: String) {
    let _ = send(
        socket,
        &Frame::ServiceError {
            id: id.into(),
            error,
        },
    )
    .await;
}
async fn service_upgrade(State(g): State<Arc<Gateway>>, ws: WebSocketUpgrade) -> Response {
    let Ok(permit) = g.handshakes.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Relay payloads are end-to-end encrypted records bounded near 64 KiB.
    ws.max_message_size(131072)
        .max_frame_size(131072)
        .on_upgrade(move |s| async move {
            let _ = g.service_connection(s, permit).await;
        })
}
struct RelayGuard {
    gateway: Arc<Gateway>,
    chain: String,
}
impl Drop for RelayGuard {
    fn drop(&mut self) {
        let mut relays = self.gateway.relays.lock().unwrap();
        if let Some(count) = relays.get_mut(&self.chain) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                relays.remove(&self.chain);
            }
        }
    }
}
async fn send(s: &mut WebSocket, f: &Frame) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(10),
        s.send(Message::Text(serde_json::to_string(f)?.into())),
    )
    .await??;
    Ok(())
}
async fn receive(s: &mut WebSocket) -> Result<Frame> {
    loop {
        match s.next().await {
            Some(Ok(Message::Text(t))) => return Ok(serde_json::from_str(&t)?),
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => anyhow::bail!("Session closed"),
        }
    }
}
async fn upgrade(
    State(g): State<Arc<Gateway>>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if headers.get_all("x-wayfinder-agent-protocol").iter().count() > 1 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let version = match headers
        .get("x-wayfinder-agent-protocol")
        .and_then(|v| v.to_str().ok())
    {
        None | Some("2") => SESSION_VERSION,
        Some("3") => CODE_SESSION_VERSION,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Ok(permit) = g.handshakes.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Two 1 MiB streams can expand sixfold when JSON escapes control bytes.
    ws.max_message_size(16 * 1024 * 1024)
        .max_frame_size(16 * 1024 * 1024)
        .on_upgrade(move |s| async move {
            let _ = g.connection(s, permit, version).await;
        })
}
async fn challenge(State(g): State<Arc<Gateway>>) -> Response {
    let nonce = g.challenge();
    Json(serde_json::json!({"version":1,"gateway":g.issuer,"nonce":nonce})).into_response()
}
async fn admit(
    State(g): State<Arc<Gateway>>,
    Json(a): Json<wayfinder_core::security::Admission>,
) -> Response {
    let result = (|| {
        let _administration = g.administration.lock().unwrap();
        let expiry = g.verify_challenge(&a.nonce)?;
        g.store.admit(&a, &g.issuer, expiry)
    })();
    match result {
        Ok(()) => Json(serde_json::json!({"admitted":true})).into_response(),
        Err(_) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"Admission denied"})),
        )
            .into_response(),
    }
}
async fn operation(State(g): State<Arc<Gateway>>, Json(s): Json<SignedOperation>) -> Response {
    match g.operate(s){Ok(v)=>Json(v).into_response(),Err(_)=>(StatusCode::FORBIDDEN,Json(serde_json::json!({"error":"Operation denied: check device role, connection, challenge, request and revocation"}))).into_response()}
}
async fn edge_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !host
        .parse::<axum::http::uri::Authority>()
        .is_ok_and(|a| matches!(a.host(), "localhost" | "127.0.0.1" | "[::1]" | "::1"))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if (req.uri().path().starts_with("/device/") || req.uri().path() == "/agent")
        && req.headers().contains_key("origin")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut r = next.run(req).await;
    r.headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    r
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl wayfinder_mcp::Routing for Gateway {
    fn code<'a>(
        &'a self,
        client: ClientIdentity,
        mut input: CodeInput,
        cancel: CancellationToken,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CodeResult> + Send + 'a>> {
        Box::pin(async move {
            let mut dispatched = false;
            let result: Result<CodeResult> = async {
                ensure!(client.permissions.contains(&wayfinder_core::credentials::Capability::Exec), "Execution permission required for code intelligence");
                input.validate()?;
                let devices = self.store.devices(&client.chain_id)?;
                let matches: Vec<_> = devices.iter().filter(|d| !d.revoked && (d.id == input.target || d.name == input.target)).collect();
                ensure!(matches.len() == 1, "Target missing or ambiguous in this Sync Chain");
                input.target = matches[0].id.clone();
                let session = self.sessions.lock().unwrap().get(&(client.chain_id.clone(), input.target.clone())).cloned().ok_or_else(|| anyhow::anyhow!("Device offline"))?;
                ensure!(session.code, "This device's agent does not support code intelligence; update Wayfinder on that device");
                ensure!(!cancel.is_cancelled(), "Code operation cancelled before dispatch");
                let local = cancel.child_token(); let _cleanup = CancelOnDrop(local.clone());
                let (tx, rx) = oneshot::channel();
                let timeout = input.timeout.unwrap_or(DEFAULT_TIMEOUT) + 15000;
                session.send.try_send(AgentEvent::Code(CodeDispatch { id: random_secret(), input: input.clone(), response: tx, cancel: local })).map_err(|_| anyhow::anyhow!("Device unavailable or busy"))?;
                dispatched = true;
                tokio::select! {
                    _ = cancel.cancelled() => anyhow::bail!("Code operation cancelled; dispatch may have occurred. No automatic retry"),
                    response = tokio::time::timeout(Duration::from_millis(timeout), rx) => {
                        let mut result = response.map_err(|_| anyhow::anyhow!("Outcome unknown: response deadline exceeded. No automatic retry"))?.map_err(|_| anyhow::anyhow!("Outcome unknown: device disconnected. No automatic retry"))?;
                        result.target = input.target.clone(); Ok(result)
                    }
                }
            }.await;
            result.unwrap_or_else(|error| {
                let mut result = CodeResult::failed(&input, error);
                result.outcome_unknown = dispatched;
                result
            })
        })
    }

    fn nodes<'a>(
        &'a self,
        chain: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        Box::pin(async move { self.nodes(chain) })
    }
    fn execute<'a>(
        &'a self,
        client: ClientIdentity,
        input: ExecInput,
        cancel: CancellationToken,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ExecResult> + Send + 'a>> {
        Box::pin(async move {
            let target = input.target.clone().unwrap_or_default();
            let result:Result<ExecResult>=async{
 input.validate()?;ensure!(!target.is_empty(),"Explicit target required");let devices=self.store.devices(&client.chain_id)?;let matches:Vec<_>=devices.iter().filter(|d|!d.revoked&&(d.id==target||d.name==target)).collect();ensure!(matches.len()==1,"Target missing or ambiguous in this Sync Chain");let id=matches[0].id.clone();let session=self.sessions.lock().unwrap().get(&(client.chain_id.clone(),id.clone())).cloned().ok_or_else(||anyhow::anyhow!("Device offline"))?;
 let local=cancel.child_token();let _cleanup=CancelOnDrop(local.clone());let(tx,rx)=oneshot::channel();let timeout=input.timeout.unwrap_or(30000)+15000;
 session.send.try_send(AgentEvent::Exec(Dispatch{id:random_secret(),input,response:tx,cancel:local})).map_err(|_|anyhow::anyhow!("Device unavailable or busy"))?;
 tokio::select!{_=cancel.cancelled()=>anyhow::bail!("Execution cancelled; dispatch may have occurred"),r=tokio::time::timeout(Duration::from_millis(timeout),rx)=>{let mut result=r.map_err(|_|anyhow::anyhow!("Outcome unknown: response deadline exceeded; command will not be retried"))?.map_err(|_|anyhow::anyhow!("Outcome unknown: device disconnected; command will not be retried"))?;result.target=id;Ok(result)}}
 }.await;
            result.unwrap_or_else(|e| ExecResult::failed(target, e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenges_allocate_only_after_authentication_and_survive_reconnect() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("wayfinder-challenge-{}", random_secret()));
        let store = Arc::new(CredentialStore::open(dir.join("registry.sqlite"))?);
        let g = Gateway::new("http://127.0.0.1:12345".into(), store.clone())?;
        for _ in 0..5000 {
            assert!(g.verify_challenge(&g.challenge()).is_ok());
        }
        assert!(g.nonces.lock().unwrap().is_empty());
        let device = identity::new_key();
        let root = identity::new_key();
        let cert = Certificate::issue(&root, &device, "Test".into(), Role::Admin)?;
        let nonce = g.challenge();
        let signature =
            identity::sign(&root, &security::admission_proof(&cert, &g.issuer, &nonce)?);
        store.admit(
            &security::Admission {
                certificate: cert.clone(),
                nonce,
                signature,
            },
            &g.issuer,
            now() + 30,
        )?;
        store.register(&cert, None)?;
        let key = (cert.chain_id.clone(), cert.device_id.clone());
        let (send, _) = mpsc::channel(1);
        let session = Session {
            generation: random_secret(),
            code: false,
            send,
            stop: CancellationToken::new(),
        };
        g.sessions
            .lock()
            .unwrap()
            .insert(key.clone(), session.clone());
        let nonce = g.challenge();
        let signature = identity::sign(
            &device,
            &operation_proof(&g.issuer, &nonce, &cert, &Operation::Devices)?,
        );
        let request = |signature: String| SignedOperation {
            certificate: cert.clone(),
            nonce: nonce.clone(),
            operation: Operation::Devices,
            signature,
        };
        assert!(g.operate(request("00".repeat(64))).is_err());
        assert!(g.nonces.lock().unwrap().is_empty());
        assert!(g.operate(request(signature.clone())).is_ok());
        g.sessions.lock().unwrap().remove(&key);
        g.sessions.lock().unwrap().insert(key, session);
        assert!(g.operate(request(signature)).is_err());
        assert!(g.verify_challenge(&format!("{nonce}0")).is_err());
        let restarted = Gateway::new(g.issuer.clone(), store.clone())?;
        assert!(restarted.verify_challenge(&nonce).is_err());
        // Valid MAC with an expired deadline must still fail.
        let payload = format!("{}.{}", now(), random_secret());
        let mut mac = Hmac::<Sha256>::new_from_slice(g.challenge_key.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        assert!(
            g.verify_challenge(&format!(
                "{payload}.{}",
                hex::encode(mac.finalize().into_bytes())
            ))
            .is_err()
        );
        drop(restarted);
        drop(g);
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[tokio::test]
    async fn code_routing_requires_exec_and_authenticated_capability_without_retry() -> Result<()> {
        use wayfinder_core::credentials::Capability;
        use wayfinder_mcp::Routing;
        let dir = std::env::temp_dir().join(format!("wayfinder-code-routing-{}", random_secret()));
        let store = Arc::new(CredentialStore::open(dir.join("registry.sqlite"))?);
        let gateway = Gateway::new("http://127.0.0.1:12345".into(), store.clone())?;
        let root = identity::new_key();
        let device = identity::new_key();
        let certificate = Certificate::issue(&root, &device, "code-target".into(), Role::Admin)?;
        let nonce = gateway.challenge();
        store.admit(
            &security::Admission {
                certificate: certificate.clone(),
                signature: identity::sign(
                    &root,
                    &security::admission_proof(&certificate, &gateway.issuer, &nonce)?,
                ),
                nonce,
            },
            &gateway.issuer,
            now() + 30,
        )?;
        store.register(&certificate, None)?;
        let (send, mut receive) = mpsc::channel(4);
        let mut session = Session {
            generation: random_secret(),
            code: false,
            send,
            stop: CancellationToken::new(),
        };
        let key = (certificate.chain_id.clone(), certificate.device_id.clone());
        gateway
            .sessions
            .lock()
            .unwrap()
            .insert(key.clone(), session.clone());
        let mut client = ClientIdentity {
            id: random_secret(),
            chain_id: certificate.chain_id.clone(),
            name: "test".into(),
            client_id: "test".into(),
            permissions: std::collections::BTreeSet::from([Capability::Read]),
            created: now(),
            revoked: None,
        };
        let input = CodeInput {
            target: "code-target".into(),
            action: wayfinder_core::code::CodeAction::Status,
            project: None,
            tool: None,
            arguments: None,
            timeout: Some(1000),
        };
        assert!(
            Routing::code(
                &*gateway,
                client.clone(),
                input.clone(),
                CancellationToken::new()
            )
            .await
            .is_error()
        );
        client.permissions.insert(Capability::Exec);
        assert!(
            Routing::code(
                &*gateway,
                client.clone(),
                input.clone(),
                CancellationToken::new()
            )
            .await
            .error
            .unwrap()
            .contains("update")
        );
        assert!(receive.try_recv().is_err());
        session.code = true;
        gateway.sessions.lock().unwrap().insert(key, session);
        let mut foreign = client.clone();
        foreign.chain_id = random_secret();
        assert!(
            Routing::code(&*gateway, foreign, input.clone(), CancellationToken::new())
                .await
                .is_error()
        );
        assert!(receive.try_recv().is_err());
        let operation = Routing::code(
            &*gateway,
            client.clone(),
            input.clone(),
            CancellationToken::new(),
        );
        let backend = async {
            let Some(AgentEvent::Code(dispatch)) = receive.recv().await else {
                panic!("expected one code dispatch")
            };
            assert_eq!(dispatch.input.target, certificate.device_id);
            let mut result = CodeResult::success(
                &dispatch.input,
                serde_json::json!({"isError":false,"content":[]}),
            );
            result.target = "spoofed".into();
            assert!(dispatch.response.send(result).is_ok());
        };
        let (result, ()) = tokio::join!(operation, backend);
        assert!(!result.is_error());
        assert_eq!(result.target, certificate.device_id);
        let operation = Routing::code(&*gateway, client, input, CancellationToken::new());
        let disconnect = async {
            let Some(AgentEvent::Code(dispatch)) = receive.recv().await else {
                panic!("expected code dispatch")
            };
            drop(dispatch.response);
        };
        let (result, ()) = tokio::join!(operation, disconnect);
        assert!(result.is_error());
        assert!(result.outcome_unknown);
        assert!(receive.try_recv().is_err());
        drop(receive);
        drop(gateway);
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
