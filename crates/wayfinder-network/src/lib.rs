//! Symmetric direct peer routing; signed membership histories, no elected hub.
mod transport;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use transport::Channel;
use wayfinder_core::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u32,
    pub network_id: String,
    pub network_name: String,
    pub inviter: Node,
    pub secret: String,
    pub expires: u64,
}
impl Invitation {
    pub fn encode(&self) -> Result<String> {
        Ok(format!(
            "wayfinder1:{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?)
        ))
    }
    pub fn decode(s: &str) -> Result<Self> {
        ensure!(s.len() < 8192, "Invitation too long");
        let i: Self = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(
                s.trim()
                    .strip_prefix("wayfinder1:")
                    .context("Invalid invitation prefix")?,
            )?,
        )?;
        ensure!(
            i.version == VERSION && i.expires > now() && i.expires <= now() + 600,
            "Expired or invalid invitation"
        );
        key_bytes(&i.secret)?;
        key_bytes(&i.network_id)?;
        i.inviter.validate()?;
        Ok(i)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Preview { invitation: Invitation },
    Join { invitation: Invitation, node: Node },
    Sync { membership: Membership },
    Exec { head: String, input: ExecInput },
    Ping,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Response {
    Membership(Membership),
    Result(ExecResult),
    Preview {
        network_id: String,
        network_name: String,
        introducer: String,
    },
    Pong,
    Error(String),
}
struct InviteRecord {
    expires: u64,
    network_id: String,
}
struct State {
    persistent: Persistent,
    reachable: BTreeMap<String, bool>,
    invites: BTreeMap<String, InviteRecord>,
}
pub struct Network {
    pub config: Config,
    pub node: Node,
    identity: Identity,
    path: PathBuf,
    state: Mutex<State>,
    admin: Mutex<()>,
    sync: Mutex<()>,
    execution_slots: Arc<Semaphore>,
    pub shutdown: CancellationToken,
}
impl Network {
    pub fn new(
        config: Config,
        identity: Identity,
        path: PathBuf,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        let persistent = load_state(&path)?;
        let node = identity.descriptor(&config)?;
        node.validate()?;
        if let Some(stored) = persistent
            .membership
            .nodes()
            .iter()
            .find(|n| n.id == node.id)
        {
            ensure!(
                stored == &node,
                "Linked node name/endpoint differs from durable membership; restore config or remove and rejoin with a fresh identity"
            );
        }
        Ok(Arc::new(Self {
            config,
            node,
            identity,
            path,
            state: Mutex::new(State {
                persistent,
                reachable: BTreeMap::new(),
                invites: BTreeMap::new(),
            }),
            admin: Mutex::new(()),
            sync: Mutex::new(()),
            execution_slots: Arc::new(Semaphore::new(16)),
            shutdown,
        }))
    }
    fn persist(&self, s: &Persistent) -> Result<()> {
        atomic_write(&self.path, s)
    }
    async fn membership(&self) -> Membership {
        self.state.lock().await.persistent.membership.clone()
    }
    async fn ensure_active(&self) -> Result<()> {
        let s = self.state.lock().await;
        ensure!(
            !s.persistent.conflict,
            "Membership conflict: administration and peer execution are blocked"
        );
        ensure!(
            s.persistent
                .membership
                .nodes()
                .iter()
                .any(|n| n.id == self.node.id),
            "This node is not an active network member"
        );
        Ok(())
    }
    async fn authorize(&self, key: &str) -> Result<Node> {
        self.ensure_active().await?;
        self.state
            .lock()
            .await
            .persistent
            .membership
            .nodes()
            .iter()
            .find(|n| n.noise_key == key)
            .cloned()
            .context("Untrusted or revoked peer")
    }
    async fn merge(&self, incoming: Membership) -> Result<()> {
        incoming.validate()?;
        let mut s = self.state.lock().await;
        let current = &s.persistent.membership;
        ensure!(
            current.head().is_some() && incoming.revisions.first() == current.revisions.first(),
            "Wrong network trust root"
        );
        if current.extends(&incoming) {
            return Ok(());
        }
        if !incoming.extends(current) {
            let mut next = s.persistent.clone();
            next.conflict = true;
            self.persist(&next)?;
            s.persistent = next;
            bail!("Conflicting signed membership histories; explicit recovery required");
        }
        let mut next = s.persistent.clone();
        next.membership = incoming;
        self.persist(&next)?;
        s.persistent = next;
        Ok(())
    }
    async fn rpc(&self, node: &Node, request: Request, timeout: Duration) -> Result<Response> {
        tokio::time::timeout(timeout, async {
            let mut ch = Channel::connect(node.endpoint, &node.noise_key, &self.identity).await?;
            ch.send(&request).await?;
            let response = ch.receive().await?;
            match response {
                Response::Error(e) => bail!("{e}"),
                r => Ok(r),
            }
        })
        .await
        .context("Peer request timed out")?
    }
    pub async fn synchronize(&self) -> Result<()> {
        let _guard = self.sync.lock().await;
        let members = self.membership().await;
        let mut peers = JoinSet::new();
        for node in members.nodes().iter().filter(|n| n.id != self.node.id) {
            let node = node.clone();
            let membership = members.clone();
            let identity = self.identity.clone();
            peers.spawn(async move {
                let r = tokio::time::timeout(Duration::from_secs(3), async {
                    let mut c = Channel::connect(node.endpoint, &node.noise_key, &identity).await?;
                    c.send(&Request::Sync { membership }).await?;
                    c.receive::<Response>().await
                })
                .await;
                (node.id, r)
            });
        }
        let mut conflict = false;
        while let Some(r) = peers.join_next().await {
            if let Ok((id, response)) = r {
                let reachable = matches!(&response, Ok(Ok(Response::Membership(_))));
                self.state.lock().await.reachable.insert(id, reachable);
                if let Ok(Ok(Response::Membership(m))) = response
                    && self.merge(m).await.is_err()
                {
                    conflict = true;
                }
            }
        }
        if conflict {
            bail!("Membership synchronization conflict; inspect network status");
        }
        Ok(())
    }
    pub async fn status(&self) -> Status {
        let s = self.state.lock().await;
        let m = &s.persistent.membership;
        let nodes = if m.head().is_none() {
            vec![self.node.clone()]
        } else {
            m.nodes().to_vec()
        };
        Status {
            node: self.node.clone(),
            network_id: m.head().map(|h| h.network_id.clone()),
            network_name: m.head().map(|h| h.name.clone()),
            nodes: nodes
                .iter()
                .map(|n| NodeStatus {
                    id: n.id.clone(),
                    name: n.name.clone(),
                    local: n.id == self.node.id,
                    reachable: n.id == self.node.id
                        || s.reachable.get(&n.id).copied().unwrap_or(false),
                })
                .collect(),
            mcp_listen: self.config.mcp_listen,
            mcp_authenticated: true,
            peer_listen: self.config.peer_listen,
            conflict: s.persistent.conflict,
            revision: m.revisions.len(),
        }
    }
    pub async fn details(&self, id: &str) -> Result<Node> {
        if id == self.node.id {
            return Ok(self.node.clone());
        }
        self.membership()
            .await
            .nodes()
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .context("Unknown node")
    }
    pub async fn create(&self, name: String) -> Result<()> {
        valid_name(&name)?;
        let _admin = self.admin.lock().await;
        let mut s = self.state.lock().await;
        ensure!(
            s.persistent.membership.head().is_none(),
            "Already in a network"
        );
        let mut p = s.persistent.clone();
        p.membership.revisions.push(Revision::sign(
            random_secret(),
            name,
            None,
            vec![self.node.clone()],
            &self.identity,
        )?);
        self.persist(&p)?;
        s.persistent = p;
        Ok(())
    }
    pub async fn invite(&self, ttl: u64) -> Result<String> {
        ensure!(
            (1..=600).contains(&ttl),
            "Invitation lifetime must be 1–600 seconds"
        );
        self.synchronize().await?;
        self.ensure_active().await?;
        let mut s = self.state.lock().await;
        let h = s
            .persistent
            .membership
            .head()
            .context("Create a network first")?;
        let i = Invitation {
            version: VERSION,
            network_id: h.network_id.clone(),
            network_name: h.name.clone(),
            inviter: self.node.clone(),
            secret: random_secret(),
            expires: now() + ttl,
        };
        s.invites.retain(|_, i| i.expires > now());
        ensure!(s.invites.len() < 64, "Too many outstanding invitations");
        s.invites.insert(
            digest(i.secret.as_bytes()),
            InviteRecord {
                expires: i.expires,
                network_id: i.network_id.clone(),
            },
        );
        i.encode()
    }
    async fn check_invite(&self, i: &Invitation) -> Result<()> {
        ensure!(
            i.version == VERSION && i.expires > now() && i.inviter == self.node,
            "Expired or invalid invitation"
        );
        self.ensure_active().await?;
        let s = self.state.lock().await;
        let record = s
            .invites
            .get(&digest(i.secret.as_bytes()))
            .context("Invitation expired, used, or invalidated by daemon restart")?;
        ensure!(
            record.expires == i.expires
                && record.network_id == i.network_id
                && s.persistent
                    .membership
                    .head()
                    .is_some_and(|h| h.name == i.network_name && h.network_id == i.network_id),
            "Invitation binding mismatch"
        );
        Ok(())
    }
    pub async fn preview(&self, encoded: &str) -> Result<serde_json::Value> {
        let i = Invitation::decode(encoded)?;
        match self
            .rpc(
                &i.inviter.clone(),
                Request::Preview { invitation: i },
                Duration::from_secs(5),
            )
            .await?
        {
            Response::Preview {
                network_id,
                network_name,
                introducer,
            } => Ok(
                serde_json::json!({"network_id":network_id,"network_name":network_name,"introducer":introducer}),
            ),
            _ => bail!("Invalid preview response"),
        }
    }
    pub async fn join(&self, encoded: &str) -> Result<()> {
        let _admin = self.admin.lock().await;
        ensure!(
            self.membership().await.head().is_none(),
            "Already in a network"
        );
        let i = Invitation::decode(encoded)?;
        let response = self
            .rpc(
                &i.inviter.clone(),
                Request::Join {
                    invitation: i.clone(),
                    node: self.node.clone(),
                },
                Duration::from_secs(15),
            )
            .await?;
        let Response::Membership(m) = response else {
            bail!("Invalid join response")
        };
        m.validate()?;
        let h = m.head().context("Empty joined membership")?;
        ensure!(
            h.network_id == i.network_id
                && h.name == i.network_name
                && h.nodes.contains(&self.node)
                && h.nodes.contains(&i.inviter),
            "Joined membership does not match invitation"
        );
        let mut s = self.state.lock().await;
        let p = Persistent {
            version: VERSION,
            membership: m,
            conflict: false,
        };
        self.persist(&p)?;
        s.persistent = p;
        drop(s);
        self.synchronize().await?;
        Ok(())
    }
    async fn add(&self, i: Invitation, node: Node, remote: &str) -> Result<Membership> {
        ensure!(
            node.noise_key == remote,
            "Joining identity does not match authenticated transport"
        );
        node.validate()?;
        let _admin = self.admin.lock().await;
        self.check_invite(&i).await?;
        self.synchronize().await?;
        self.ensure_active().await?;
        let mut s = self.state.lock().await;
        let mut p = s.persistent.clone();
        let h = p.membership.head().context("Missing network")?;
        ensure!(
            !h.nodes
                .iter()
                .any(|n| n.id == node.id || n.name == node.name || n.noise_key == node.noise_key),
            "Node ID, name or key already belongs to network"
        );
        let mut nodes = h.nodes.clone();
        nodes.push(node);
        let r = Revision::sign(
            h.network_id.clone(),
            h.name.clone(),
            Some(h.hash()?),
            nodes,
            &self.identity,
        )?;
        p.membership.revisions.push(r);
        p.membership.validate()?;
        // Recheck expiry after synchronization; remove before commit, never reusable after success.
        ensure!(i.expires > now(), "Invitation expired");
        ensure!(
            s.invites.remove(&digest(i.secret.as_bytes())).is_some(),
            "Invitation already used"
        );
        self.persist(&p)?;
        let m = p.membership.clone();
        s.persistent = p;
        Ok(m)
    }
    pub async fn remove(&self, id: &str) -> Result<()> {
        let _admin = self.admin.lock().await;
        self.synchronize().await?;
        self.ensure_active().await?;
        ensure!(id != self.node.id, "Remove this node from another member");
        let mut s = self.state.lock().await;
        let mut p = s.persistent.clone();
        let h = p.membership.head().context("Missing network")?;
        let nodes: Vec<_> = h.nodes.iter().filter(|n| n.id != id).cloned().collect();
        ensure!(nodes.len() + 1 == h.nodes.len(), "Unknown node");
        p.membership.revisions.push(Revision::sign(
            h.network_id.clone(),
            h.name.clone(),
            Some(h.hash()?),
            nodes,
            &self.identity,
        )?);
        p.membership.validate()?;
        self.persist(&p)?;
        s.persistent = p;
        drop(s);
        self.synchronize().await?;
        Ok(())
    }
    pub async fn execute(&self, input: ExecInput, cancel: CancellationToken) -> ExecResult {
        let requested = input.target.clone().unwrap_or_else(|| self.node.id.clone());
        if let Err(e) = input.validate() {
            return ExecResult::failed(requested, e);
        }
        let membership = self.membership().await;
        let target = if requested == self.node.id {
            Some(self.node.clone())
        } else if let Some(node) = membership.nodes().iter().find(|n| n.id == requested) {
            Some(node.clone())
        } else if requested == self.node.name {
            Some(self.node.clone())
        } else {
            membership
                .nodes()
                .iter()
                .find(|n| n.name == requested)
                .cloned()
        };
        let Some(target) = target else {
            return ExecResult::failed(requested, "Unknown target; nothing executed");
        };
        if target.id == self.node.id {
            return self.local(input, cancel).await;
        }
        if let Err(e) = self.ensure_active().await {
            return ExecResult::failed(target.id, e);
        }
        let timeout = Duration::from_millis(input.timeout.unwrap_or(30_000) + 5000);
        let m = self.membership().await;
        let head = match m.head().and_then(|h| h.hash().ok()) {
            Some(h) => h,
            None => return ExecResult::failed(target.id, "Missing membership"),
        };
        let mut input = input;
        input.target = Some(target.id.clone());
        tokio::select! {
            _=cancel.cancelled()=>ExecResult::failed(target.id.clone(), "Execution cancelled; peer connection closed"),
            _=self.shutdown.cancelled()=>ExecResult::failed(target.id.clone(), "Daemon shutting down"),
            r=self.route(&target, Request::Exec{head,input},timeout)=>r,
        }
    }
    async fn route(&self, target: &Node, request: Request, timeout: Duration) -> ExecResult {
        let setup = tokio::time::timeout(
            Duration::from_secs(3),
            Channel::connect(target.endpoint, &target.noise_key, &self.identity),
        )
        .await;
        let mut channel = match setup {
            Ok(Ok(channel)) => channel,
            _ => {
                return ExecResult::failed(
                    target.id.clone(),
                    "Target unreachable or peer authentication failed before dispatch; nothing executed; no fallback",
                );
            }
        };
        let exchange = tokio::time::timeout(timeout, async {
            channel.send(&request).await?;
            channel.receive::<Response>().await
        })
        .await;
        match exchange {
            Ok(Ok(Response::Result(r))) if r.target == target.id => r,
            Ok(Ok(Response::Error(e))) => {
                ExecResult::failed(target.id.clone(), format!("Target rejected execution: {e}"))
            }
            _ => ExecResult::failed(
                target.id.clone(),
                "Peer connection lost or invalid response after dispatch; execution outcome unknown; no fallback or retry",
            ),
        }
    }
    async fn local(&self, input: ExecInput, cancel: CancellationToken) -> ExecResult {
        let permit = match self.execution_slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return ExecResult::failed(self.node.id.clone(), "Execution capacity reached");
            }
        };
        let local_cancel = cancel.child_token();
        let result = tokio::select! {r=wayfinder_exec::execute(self.node.id.clone(),input,local_cancel.clone())=>r,_=self.shutdown.cancelled()=>{local_cancel.cancel();ExecResult::failed(self.node.id.clone(),"Daemon shutting down")}};
        drop(permit);
        result
    }
    async fn handle(&self, ch: &mut Channel, request: Request) -> Result<Response> {
        match request {
            Request::Preview { invitation: i } => {
                self.check_invite(&i).await?;
                Ok(Response::Preview {
                    network_id: i.network_id,
                    network_name: i.network_name,
                    introducer: self.node.name.clone(),
                })
            }
            Request::Join { invitation, node } => Ok(Response::Membership(
                self.add(invitation, node, &ch.remote).await?,
            )),
            Request::Sync { membership } => {
                // A returning retained node may never have seen a newly added peer.
                // Its signed extension from our pinned genesis proves that peer's membership.
                let current = self.membership().await;
                let known = current.nodes().iter().any(|n| n.noise_key == ch.remote);
                if !known {
                    membership.validate()?;
                    ensure!(
                        current.head().is_some()
                            && membership.extends(&current)
                            && membership.nodes().iter().any(|n| n.noise_key == ch.remote),
                        "Untrusted or revoked synchronization peer"
                    );
                }
                self.merge(membership).await?;
                Ok(Response::Membership(self.membership().await))
            }
            Request::Ping => {
                self.authorize(&ch.remote).await?;
                Ok(Response::Pong)
            }
            Request::Exec { head, input } => {
                self.authorize(&ch.remote).await?;
                ensure!(
                    input.target.as_deref() == Some(&self.node.id),
                    "Routed target must be this exact node"
                );
                let m = self.membership().await;
                ensure!(
                    m.head().context("Missing membership")?.hash()? == head,
                    "Membership differs; synchronize before execution"
                );
                let cancel = self.shutdown.child_token();
                let future = self.local(input, cancel.clone());
                tokio::pin!(future);
                let r = tokio::select! {r=&mut future=>r,_=ch.disconnected()=>{cancel.cancel();future.await}};
                Ok(Response::Result(r))
            }
        }
    }
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        let slots = Arc::new(Semaphore::new(64));
        let mut tasks = JoinSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let background = self.clone();
        let sync_task = tokio::spawn(async move {
            loop {
                tokio::select! {_=background.shutdown.cancelled()=>break,_=interval.tick()=>{let _=background.synchronize().await;}}
            }
        });
        loop {
            tokio::select! {_=self.shutdown.cancelled()=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},accepted=listener.accept()=>{let (stream,_)=accepted?;let Ok(permit)=slots.clone().try_acquire_owned()else{drop(stream);continue;};let network=self.clone();tasks.spawn(async move{let _permit=permit;let setup=tokio::time::timeout(Duration::from_secs(5),async{let mut ch=Channel::accept(stream,&network.identity).await?;let req=ch.receive::<Request>().await?;Ok::<_,anyhow::Error>((ch,req))}).await;let Ok(Ok((mut ch,req)))=setup else{return;};let response=match network.handle(&mut ch,req).await{Ok(r)=>r,Err(e)=>Response::Error(e.to_string())};let _=tokio::time::timeout(Duration::from_secs(5),ch.send(&response)).await;});}}
        }
        sync_task.abort();
        let _ = sync_task.await;
        // Cancellation reaches executions first; bound shutdown even for incomplete admin traffic.
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}
