//! The official MCP SDK owns Streamable HTTP and protocol lifecycle.
mod oauth;
use axum::{
    Router,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::sync::Arc;
use tokio::net::TcpListener;
use wayfinder_core::credentials::{Capability, ClientIdentity, CredentialStore};
use wayfinder_core::{ExecInput, bearer_value};
use wayfinder_network::Network;
#[derive(Clone)]
struct Mcp {
    network: Arc<Network>,
    issuer: Option<String>,
    tools: ToolRouter<Self>,
}
#[tool_router]
impl Mcp {
    fn new(network: Arc<Network>, issuer: Option<String>) -> Self {
        let mut tools = Self::tool_router();
        if issuer.is_some() {
            for (name, scope) in [("nodes", "read"), ("exec", "exec")] {
                // rmcp has no top-level securitySchemes field. Use OpenAI's
                // documented compatibility representation in native Tool.meta.
                let mut meta = MetaObject::new();
                meta.insert(
                    "securitySchemes".into(),
                    serde_json::json!([{"type":"oauth2","scopes":[scope]}]),
                );
                tools.map.get_mut(name).unwrap().attr.meta = Some(meta);
            }
        }
        Self {
            network,
            issuer,
            tools,
        }
    }
    fn capability_error(&self, error: ErrorData, scope: &str) -> Result<CallToolResult, ErrorData> {
        let Some(issuer) = &self.issuer else {
            return Err(error);
        };
        let challenge = format!(
            "Bearer error=\"insufficient_scope\", error_description=\"Credential lacks the required capability\", scope=\"{scope}\", resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\""
        );
        let mut meta = MetaObject::new();
        meta.insert(
            "mcp/www_authenticate".into(),
            serde_json::json!([challenge]),
        );
        Ok(CallToolResult::error(vec![ContentBlock::text(
            "Credential lacks the required capability",
        )])
        .with_meta(Some(meta)))
    }
    #[tool(
        description = "Discover Wayfinder nodes: stable ID, unique name, entry node and last observed reachability."
    )]
    async fn nodes(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(error) = require(&context, Capability::Read) {
            return self.capability_error(error, "read");
        }
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
        if let Err(error) = require(&context, Capability::Exec) {
            return self.capability_error(error, "exec");
        }
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
#[tool_handler(router = self.tools)]
impl ServerHandler for Mcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(Implementation::new("wayfinder",env!("CARGO_PKG_VERSION"))).with_instructions("Use nodes to choose a target, then exec. Commands execute as the target daemon's OS account.")
    }
}
fn require(context: &RequestContext<RoleServer>, permission: Capability) -> Result<(), ErrorData> {
    let client = context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ClientIdentity>());
    if client.is_some_and(|client| client.permissions.contains(&permission)) {
        Ok(())
    } else {
        Err(ErrorData::invalid_request(
            "Credential lacks the required capability",
            None,
        ))
    }
}
#[derive(Clone)]
struct Ingress {
    network: Arc<Network>,
    credentials: Arc<CredentialStore>,
    oauth: Option<Arc<wayfinder_core::oauth::OAuth>>,
}
async fn guard(State(ingress): State<Ingress>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let oauth_path = ingress.oauth.is_some()
        && matches!(
            path,
            "/.well-known/oauth-protected-resource"
                | "/.well-known/oauth-authorization-server"
                | "/oauth/authorize"
                | "/oauth/continue"
                | "/oauth/token"
        );
    if path != "/" && !oauth_path {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path == "/" && req.uri().query().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let origin = req.headers().get("origin");
    if origin.is_some_and(|v| {
        !oauth_path
            || ingress
                .oauth
                .as_ref()
                .is_none_or(|o| v.to_str().ok() != Some(o.issuer.as_str()))
    }) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Both SDK and ingress require the proxy to rewrite Host to loopback.
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
    if ingress.network.shutdown.is_cancelled() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if oauth_path {
        return secured(next.run(req).await);
    }
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_value)
        .unwrap_or("");
    let client = if req.headers().get_all("authorization").iter().count() == 1 {
        ingress
            .credentials
            .authenticate(token, ingress.oauth.as_ref().map(|o| o.issuer.as_str()))
    } else {
        Ok(None)
    };
    let client = match client {
        Ok(Some(client)) => client,
        Ok(None) => {
            let challenge = match &ingress.oauth {
                Some(o) => format!(
                    "Bearer realm=\"wayfinder\", resource_metadata=\"{}/.well-known/oauth-protected-resource\", scope=\"read exec\"",
                    o.issuer
                ),
                None => "Bearer realm=\"wayfinder\"".to_string(),
            };
            return (
                StatusCode::UNAUTHORIZED,
                [
                    ("www-authenticate", challenge),
                    ("cache-control", "no-store".to_string()),
                ],
                "Unauthorized",
            )
                .into_response();
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    // The SDK propagates HTTP extensions into each stateless request context.
    // Strip the raw bearer before dispatch; only the public identity travels on.
    req.headers_mut().remove("authorization");
    req.extensions_mut().insert(client);
    secured(next.run(req).await)
}
fn secured(mut response: Response) -> Response {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        ),
    ] {
        response.headers_mut().insert(name, value.parse().unwrap());
    }
    response
}
pub async fn serve(
    listener: TcpListener,
    network: Arc<Network>,
    credentials: Arc<CredentialStore>,
    oauth: Option<Arc<wayfinder_core::oauth::OAuth>>,
) -> anyhow::Result<()> {
    let factory = network.clone();
    let issuer = oauth.as_ref().map(|o| o.issuer.clone());
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true);
    let mut config = config;
    config.cancellation_token = network.shutdown.clone();
    config.max_request_body_bytes = 131072;
    let service = StreamableHttpService::new(
        move || Ok(Mcp::new(factory.clone(), issuer.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let ingress = Ingress {
        network: network.clone(),
        credentials,
        oauth,
    };
    let app = Router::new()
        .route_service("/", service)
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(oauth::resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(oauth::metadata),
        )
        .route("/oauth/authorize", axum::routing::get(oauth::authorize))
        .route(
            "/oauth/continue",
            axum::routing::get(oauth::continue_authorization),
        )
        .route("/oauth/token", axum::routing::post(oauth::token))
        .layer(DefaultBodyLimit::max(131072))
        .layer(middleware::from_fn_with_state(ingress.clone(), guard))
        .with_state(ingress);
    axum::serve(listener, app)
        .with_graceful_shutdown(network.shutdown.clone().cancelled_owned())
        .await?;
    Ok(())
}
