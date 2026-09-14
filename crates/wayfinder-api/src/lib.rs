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
    Applications,
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
    data: std::path::PathBuf,
    applications: Vec<ApplicationService>,
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
    let result = if matches!(op, Operation::Applications) {
        application_services(&api.data).map(|configured| {
            serde_json::json!({
                "configured": configured, "active": api.applications,
                "changes": "Configuration changes apply at daemon restart"
            })
        })
    } else {
        dispatch(&api.network, op).await
    };
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
        Operation::Applications => unreachable!("handled by local administration"),
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
pub async fn serve(
    listener: TcpListener,
    network: Arc<Network>,
    credential: String,
    data: std::path::PathBuf,
    applications: Vec<ApplicationService>,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "Control must bind loopback"
    );
    let api = Api {
        network: network.clone(),
        credential,
        data,
        applications,
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

/// An application capability has no administration operations in its decoder.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum ServiceOperation {
    Status,
    RegisterService {
        service: String,
        address: std::net::SocketAddr,
        credential: String,
    },
    UnregisterService {
        service: String,
        credential: String,
    },
}
#[derive(Clone)]
struct ServiceApi {
    network: Arc<Network>,
    credential: String,
    service: String,
}
async fn service_guard(State(api): State<ServiceApi>, req: Request, next: Next) -> Response {
    if req.uri().path() != "/peer-service" || req.uri().query().is_some() {
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
async fn service_control(
    State(api): State<ServiceApi>,
    Json(op): Json<ServiceOperation>,
) -> Json<Reply> {
    let result: Result<serde_json::Value> = async {
        match op {
            ServiceOperation::Status => {
                let status = api.network.status().await;
                Ok(serde_json::json!({"nodes": status.nodes, "conflict": status.conflict}))
            }
            ServiceOperation::RegisterService {
                service,
                address,
                credential,
            } => {
                ensure!(service == api.service, "Service outside capability scope");
                api.network
                    .register_service(service, address, credential)
                    .await?;
                Ok(serde_json::json!({"version": 1, "lease_seconds": 60}))
            }
            ServiceOperation::UnregisterService {
                service,
                credential,
            } => {
                ensure!(service == api.service, "Service outside capability scope");
                api.network.unregister_service(service, credential).await?;
                Ok(serde_json::json!({"unregistered": true}))
            }
        }
    }
    .await;
    Json(match result {
        Ok(value) => Reply {
            value: Some(value),
            error: None,
        },
        Err(e) => Reply {
            value: None,
            error: Some(e.to_string()),
        },
    })
}
pub async fn serve_peer_service(
    listener: TcpListener,
    network: Arc<Network>,
    credential: String,
    service: String,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "Peer service API must bind loopback"
    );
    let api = ServiceApi {
        network: network.clone(),
        credential,
        service,
    };
    let app = Router::new()
        .route("/peer-service", post(service_control))
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(api.clone(), service_guard))
        .with_state(api);
    axum::serve(listener, app)
        .with_graceful_shutdown(network.shutdown.clone().cancelled_owned())
        .await?;
    Ok(())
}
