//! The official MCP SDK owns Streamable HTTP and protocol lifecycle.
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::sync::Arc;
use tokio::net::TcpListener;
use wayfinder_core::{ExecInput, bearer_value, secret_eq};
use wayfinder_network::Network;
#[derive(Clone)]
struct Mcp {
    network: Arc<Network>,
}
#[tool_router]
impl Mcp {
    fn new(network: Arc<Network>) -> Self {
        Self { network }
    }
    #[tool(
        description = "Discover Wayfinder nodes: stable ID, unique name, entry node and last observed reachability."
    )]
    async fn nodes(&self) -> Result<CallToolResult, ErrorData> {
        let value = serde_json::json!({"nodes":self.network.status().await.nodes});
        Ok(CallToolResult::structured(value))
    }
    #[tool(
        description = "Execute a fresh host shell as the selected node's OS account. No sandbox. Omit target for this node; otherwise use exact node ID or unique name. Timeout is 1–300000 milliseconds. No fallback or automatic retry."
    )]
    async fn exec(
        &self,
        Parameters(input): Parameters<ExecInput>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = self.network.execute(input, context.ct.clone()).await;
        let failed = result.is_error();
        let mut response = CallToolResult::structured(
            serde_json::to_value(result)
                .map_err(|_| ErrorData::internal_error("Result serialization failed", None))?,
        );
        response.is_error = Some(failed);
        Ok(response)
    }
}
#[tool_handler]
impl ServerHandler for Mcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(Implementation::new("wayfinder",env!("CARGO_PKG_VERSION"))).with_instructions("Use nodes to choose a target, then exec. Commands execute as the target daemon's OS account.")
    }
}
async fn guard(State(network): State<Arc<Network>>, req: Request, next: Next) -> Response {
    // Deliberately preserve 1f4d37c: discovery/unknown paths are never bearer challenges.
    if req.uri().path() != "/mcp" || req.uri().query().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_value)
        .unwrap_or("");
    if !secret_eq(token, &network.config.mcp_token) {
        return (
            StatusCode::UNAUTHORIZED,
            [
                ("www-authenticate", "Bearer realm=\"wayfinder\""),
                ("cache-control", "no-store"),
            ],
            "Unauthorized",
        )
            .into_response();
    }
    if req.headers().contains_key("origin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    if network.config.mcp_listen.ip().is_loopback() {
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
    }
    if network.shutdown.is_cancelled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    next.run(req).await
}
pub async fn serve(listener: TcpListener, network: Arc<Network>) -> anyhow::Result<()> {
    let factory = network.clone();
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    let mut config = config;
    config.cancellation_token = network.shutdown.clone();
    config.max_request_body_bytes = 131072;
    let service = StreamableHttpService::new(
        move || Ok(Mcp::new(factory.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let app = Router::new()
        .route_service("/mcp", service)
        .layer(DefaultBodyLimit::max(131072))
        .layer(middleware::from_fn_with_state(network.clone(), guard));
    axum::serve(listener, app)
        .with_graceful_shutdown(network.shutdown.clone().cancelled_owned())
        .await?;
    Ok(())
}
