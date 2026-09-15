//! OAuth HTTP adaptation; durable grants live in core's credential store.
use super::Ingress;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;
use wayfinder_core::oauth::{Authorization, Continue};

pub async fn resource(State(i): State<Ingress>) -> Response {
    let Some(o) = &i.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(json!({"resource":o.issuer,"authorization_servers":[o.issuer],"scopes_supported":["read","exec"],"bearer_methods_supported":["header"]})).into_response()
}
pub async fn metadata(State(i): State<Ingress>) -> Response {
    let Some(o) = &i.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(json!({"issuer":o.issuer,"authorization_endpoint":format!("{}/oauth/authorize",o.issuer),"token_endpoint":format!("{}/oauth/token",o.issuer),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":["read","exec"],"authorization_response_iss_parameter_supported":true})).into_response()
}
fn error(code: &'static str, status: StatusCode) -> Response {
    let mut response = (status, Json(json!({"error":code}))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            "Basic realm=\"wayfinder-oauth\"".parse().unwrap(),
        );
    }
    response
}
pub async fn authorize(
    State(i): State<Ingress>,
    query: Result<Query<Authorization>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Some(o) = &i.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Query(a)) = query else {
        return error("invalid_request", StatusCode::BAD_REQUEST);
    };
    match o.begin(a) {
        Ok(ticket) => Redirect::to(&format!("/oauth/continue?ticket={ticket}")).into_response(),
        // Never redirect to an unvalidated user-supplied URI.
        Err(_) => error("invalid_request", StatusCode::BAD_REQUEST),
    }
}
#[derive(Deserialize)]
pub struct Ticket {
    ticket: String,
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub async fn continue_authorization(State(i): State<Ingress>, Query(t): Query<Ticket>) -> Response {
    let Some(o) = &i.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match o.continue_authorization(&t.ticket) {
        Ok(Continue::Redirect(uri)) => Redirect::to(&uri).into_response(),
        Ok(Continue::Waiting(a)) => Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Authorize Wayfinder</title><h1>Authorize Wayfinder</h1><p>Client: {}</p><p>Redirect: {}</p><p>Requested permissions: {}</p><p>On your Wayfinder host, run <code>wayfinder auth pending</code>. Verify this request ID and redirect, then approve only if you initiated this connection.</p><pre>{}</pre><p>Execution grants shell access as the daemon account. Never approve a request supplied by someone else.</p><p>After approving, refresh this page to return to your MCP client. This request expires in ten minutes.</p></html>",escape(&a.client_name),escape(&a.redirect_uri),escape(&wayfinder_core::oauth::scope(&a.permissions)),a.id)).into_response(),
        Err(_) => error("invalid_request", StatusCode::BAD_REQUEST),
    }
}
#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: String,
    scope: Option<String>,
}
fn client_credentials(headers: &HeaderMap, form: &TokenRequest) -> Option<(String, String)> {
    if let Some(header) = headers.get("authorization") {
        if headers.get_all("authorization").iter().count() != 1 || form.client_secret.is_some() {
            return None;
        }
        let (scheme, encoded) = header.to_str().ok()?.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Basic") {
            return None;
        }
        let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        // RFC 6749: Basic client credentials are form-encoded before base64.
        let decode = |s: &str| {
            url::form_urlencoded::parse(format!("v={s}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
        };
        let id = decode(id)?;
        let secret = decode(secret)?;
        if form.client_id.as_ref().is_some_and(|value| value != &id) {
            return None;
        }
        Some((id, secret))
    } else {
        Some((form.client_id.clone()?, form.client_secret.clone()?))
    }
}
pub async fn token(
    State(i): State<Ingress>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, axum::extract::rejection::FormRejection>,
) -> Response {
    let Some(o) = &i.oauth else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Form(f)) = form else {
        return error("invalid_request", StatusCode::BAD_REQUEST);
    };
    let Some((id, secret)) = client_credentials(&headers, &f) else {
        return error("invalid_client", StatusCode::UNAUTHORIZED);
    };
    if i.credentials.oauth_client(&id, Some(&secret)).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"wayfinder-oauth\"")],
            Json(json!({"error":"invalid_client"})),
        )
            .into_response();
    }
    if f.resource != o.issuer {
        return error("invalid_target", StatusCode::BAD_REQUEST);
    }
    let result = match f.grant_type.as_str() {
        "authorization_code" => match (f.code, f.redirect_uri, f.code_verifier) {
            (Some(code), Some(uri), Some(verifier)) => {
                o.exchange(&code, &id, &uri, &f.resource, &verifier)
            }
            _ => return error("invalid_request", StatusCode::BAD_REQUEST),
        },
        "refresh_token" => match f.refresh_token {
            Some(refresh) => {
                i.credentials
                    .refresh_oauth(&refresh, &id, &f.resource, f.scope.as_deref())
            }
            None => return error("invalid_request", StatusCode::BAD_REQUEST),
        },
        _ => return error("unsupported_grant_type", StatusCode::BAD_REQUEST),
    };
    match result {
        Ok(tokens) => Json(tokens).into_response(),
        Err(_) => error("invalid_grant", StatusCode::BAD_REQUEST),
    }
}
