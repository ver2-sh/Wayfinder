//! Private loopback administration. Clients receive no execution/network manager.
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use wayfinder_core::*;
use wayfinder_network::Network;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Status,
    Details { id: String },
    Create { name: String },
    Invite { ttl: Option<u64> },
    Preview { invitation: String },
    Join { invitation: String },
    Remove { id: String, confirm: bool },
}
#[derive(Serialize, Deserialize)]
pub struct Reply {
    pub value: Option<serde_json::Value>,
    pub error: Option<String>,
}
#[derive(Clone)]
struct Api {
    network: Arc<Network>,
    credential: String,
}
pub fn allowed_host(req: &Request) -> bool {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    host.parse::<axum::http::uri::Authority>()
        .is_ok_and(|a| matches!(a.host(), "127.0.0.1" | "localhost" | "[::1]" | "::1"))
}
async fn guard(State(api): State<Api>, req: Request, next: Next) -> Response {
    if req.uri().path() != "/control" || req.uri().query().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if req.headers().contains_key("origin") || !allowed_host(&req) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_value)
        .unwrap_or("");
    if !secret_eq(token, &api.credential) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}
async fn control(State(api): State<Api>, Json(op): Json<Operation>) -> Json<Reply> {
    let result = dispatch(&api.network, op).await;
    Json(match result {
        Ok(v) => Reply {
            value: Some(v),
            error: None,
        },
        Err(e) => Reply {
            value: None,
            error: Some(e.to_string()),
        },
    })
}
async fn dispatch(network: &Network, op: Operation) -> Result<serde_json::Value> {
    match op {
        Operation::Status => Ok(serde_json::to_value(network.status().await)?),
        Operation::Details { id } => Ok(serde_json::to_value(network.details(&id).await?)?),
        Operation::Create { name } => {
            network.create(name).await?;
            Ok(serde_json::json!({"created":true}))
        }
        Operation::Invite { ttl } => {
            Ok(serde_json::json!({"invitation":network.invite(ttl.unwrap_or(600)).await?}))
        }
        Operation::Preview { invitation } => network.preview(&invitation).await,
        Operation::Join { invitation } => {
            network.join(&invitation).await?;
            Ok(serde_json::json!({"joined":true}))
        }
        Operation::Remove { id, confirm } => {
            ensure!(confirm, "Removal requires explicit confirmation");
            network.remove(&id).await?;
            Ok(serde_json::json!({"removed":true}))
        }
    }
}
pub async fn serve(listener: TcpListener, network: Arc<Network>, credential: String) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "Control must bind loopback"
    );
    let api = Api {
        network: network.clone(),
        credential,
    };
    let app = Router::new()
        .route("/control", post(control))
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(api.clone(), guard))
        .with_state(api);
    axum::serve(listener, app)
        .with_graceful_shutdown(network.shutdown.clone().cancelled_owned())
        .await?;
    Ok(())
}
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    descriptor: ControlDescriptor,
}
impl Client {
    pub fn attach(data: &Path) -> Result<Self> {
        let descriptor: ControlDescriptor = read_private(&data.join("control.json"))?;
        ensure!(
            descriptor.version == VERSION && descriptor.address.ip().is_loopback(),
            "Invalid local control descriptor"
        );
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(25))
            .build()?;
        Ok(Self { http, descriptor })
    }
    pub async fn call(&self, op: Operation) -> Result<serde_json::Value> {
        let r = self
            .http
            .post(format!("http://{}/control", self.descriptor.address))
            .bearer_auth(&self.descriptor.credential)
            .json(&op)
            .send()
            .await
            .context("Cannot reach daemon; start wayfinder daemon")?
            .error_for_status()?
            .json::<Reply>()
            .await?;
        if let Some(e) = r.error {
            anyhow::bail!("{e}");
        }
        r.value.context("Empty control response")
    }
    pub async fn status(&self) -> Result<Status> {
        Ok(serde_json::from_value(self.call(Operation::Status).await?)?)
    }
}
