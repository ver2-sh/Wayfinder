//! Installation-local authorization code + S256 PKCE flow. Consent is granted
//! exclusively over private control, never by possession of a browser URL.
use crate::{
    credentials::{Capability, CredentialStore, OAuthTokens},
    digest, now, random_secret, valid_name,
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use url::Url;

pub fn validate_issuer(value: &str) -> Result<()> {
    let u = Url::parse(value)?;
    ensure!(
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/"
            && value == u.origin().ascii_serialization(),
        "mcp_public_url must be a canonical HTTPS origin without a trailing slash"
    );
    Ok(())
}
pub fn validate_redirect(value: &str) -> Result<()> {
    ensure!(value.len() <= 2048, "Redirect URI too long");
    let u = Url::parse(value)?;
    ensure!(
        u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
            && (u.scheme() == "https"
                || (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "[::1]")))),
        "Redirect must be HTTPS (HTTP only for loopback IPs)"
    );
    Ok(())
}
pub fn permissions(value: &str) -> Result<BTreeSet<Capability>> {
    let mut result = BTreeSet::new();
    for s in value.split_whitespace() {
        result.insert(match s {
            "read" => Capability::Read,
            "exec" => Capability::Exec,
            _ => anyhow::bail!("invalid_scope"),
        });
    }
    ensure!(!result.is_empty(), "invalid_scope");
    Ok(result)
}
pub fn scope(value: &BTreeSet<Capability>) -> String {
    value
        .iter()
        .map(|c| match c {
            Capability::Read => "read",
            Capability::Exec => "exec",
        })
        .collect::<Vec<_>>()
        .join(" ")
}
#[derive(Deserialize)]
pub struct Authorization {
    #[serde(default)]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
}
/// Only errors constructed after exact client/redirect validation may leave the host.
pub enum AuthorizationError {
    Local,
    Redirect(String),
}
#[derive(Clone, Serialize)]
pub struct Approval {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub permissions: BTreeSet<Capability>,
    pub expires: u64,
}
struct Pending {
    approval: Approval,
    state: Option<String>,
    challenge: String,
    name: Option<String>,
}
struct Code {
    pending: Pending,
    expires: u64,
}
#[derive(Default)]
struct FlowState {
    pending: BTreeMap<String, Pending>,
    codes: BTreeMap<String, Code>,
}
pub struct OAuth {
    pub issuer: String,
    credentials: Arc<CredentialStore>,
    state: Mutex<FlowState>,
}
pub enum Continue {
    Waiting(Approval),
    Redirect(String),
}
impl OAuth {
    pub fn new(issuer: String, credentials: Arc<CredentialStore>) -> Result<Self> {
        validate_issuer(&issuer)?;
        Ok(Self {
            issuer,
            credentials,
            state: Mutex::new(FlowState::default()),
        })
    }
    pub fn begin(&self, a: Authorization) -> Result<String, AuthorizationError> {
        let client = self
            .credentials
            .oauth_client(&a.client_id, None)
            .map_err(|_| AuthorizationError::Local)?;
        if a.redirect_uri != client.redirect_uri {
            return Err(AuthorizationError::Local);
        }
        // Parse the registered URI, never an untrusted request URI. Keep the exact
        // comparison above; URL normalization is not redirect validation.
        let redirect = Url::parse(&client.redirect_uri).map_err(|_| AuthorizationError::Local)?;
        let failure = |code| {
            let mut uri = redirect.clone();
            let mut q = uri.query_pairs_mut();
            q.append_pair("error", code)
                .append_pair("iss", &self.issuer);
            if let Some(s) = &a.state {
                q.append_pair("state", s);
            }
            drop(q);
            AuthorizationError::Redirect(uri.into())
        };
        if a.response_type.is_empty() {
            return Err(failure("invalid_request"));
        }
        if a.response_type != "code" {
            return Err(failure("unsupported_response_type"));
        }
        if !(a.resource == self.issuer
            && a.code_challenge_method == "S256"
            && a.code_challenge.len() == 43
            && URL_SAFE_NO_PAD
                .decode(&a.code_challenge)
                .is_ok_and(|v| v.len() == 32)
            && a.state.as_ref().is_none_or(|s| s.len() <= 2048))
        {
            return Err(failure("invalid_request"));
        }
        let permissions = permissions(a.scope.as_deref().unwrap_or("read"))
            .map_err(|_| failure("invalid_scope"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("temporarily_unavailable"))?;
        state.pending.retain(|_, p| p.approval.expires > now());
        state.codes.retain(|_, c| c.expires > now());
        if state.pending.len() + state.codes.len() >= 64 {
            return Err(failure("temporarily_unavailable"));
        }
        let ticket = random_secret();
        state.pending.insert(
            digest(ticket.as_bytes()),
            Pending {
                approval: Approval {
                    id: random_secret(),
                    client_id: client.id,
                    client_name: client.name,
                    redirect_uri: client.redirect_uri,
                    permissions,
                    expires: now() + 600,
                },
                state: a.state,
                challenge: a.code_challenge,
                name: None,
            },
        );
        Ok(ticket)
    }
    pub fn pending(&self) -> Result<Vec<Approval>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        Ok(state
            .pending
            .values()
            .filter(|p| p.approval.expires > now() && p.name.is_none())
            .map(|p| p.approval.clone())
            .collect())
    }
    pub fn approve(&self, id: &str, name: String, allowed: BTreeSet<Capability>) -> Result<()> {
        valid_name(&name)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        let p = state
            .pending
            .values_mut()
            .find(|p| p.approval.id == id && p.approval.expires > now() && p.name.is_none())
            .ok_or_else(|| anyhow::anyhow!("Pending authorization not found"))?;
        ensure!(
            !allowed.is_empty() && allowed.is_subset(&p.approval.permissions),
            "Approve only requested permissions"
        );
        ensure!(
            !self.credentials.list()?.iter().any(|c| c.name == name),
            "Credential name already exists"
        );
        p.approval.permissions = allowed;
        p.name = Some(name);
        Ok(())
    }
    pub fn continue_authorization(&self, ticket: &str) -> Result<Continue> {
        crate::key_bytes(ticket)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        let key = digest(ticket.as_bytes());
        let p = state
            .pending
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("Authorization expired"))?;
        ensure!(p.approval.expires > now(), "Authorization expired");
        if p.name.is_none() {
            return Ok(Continue::Waiting(p.approval.clone()));
        }
        let p = state.pending.remove(&key).unwrap();
        let code = random_secret();
        let mut redirect = Url::parse(&p.approval.redirect_uri)?;
        {
            let mut q = redirect.query_pairs_mut();
            q.append_pair("code", &code)
                .append_pair("iss", &self.issuer);
            if let Some(s) = &p.state {
                q.append_pair("state", s);
            }
        }
        state.codes.insert(
            digest(code.as_bytes()),
            Code {
                pending: p,
                expires: now() + 60,
            },
        );
        Ok(Continue::Redirect(redirect.into()))
    }
    pub fn exchange(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        verifier: &str,
    ) -> Result<OAuthTokens> {
        ensure!(
            resource == self.issuer
                && (43..=128).contains(&verifier.len())
                && verifier
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
            "invalid_grant"
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        let c = state
            .codes
            .remove(&digest(code.as_bytes()))
            .ok_or_else(|| anyhow::anyhow!("invalid_grant"))?;
        let p = c.pending;
        ensure!(
            now() < c.expires
                && p.approval.client_id == client_id
                && p.approval.redirect_uri == redirect_uri
                && crate::secret_eq(
                    &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                    &p.challenge
                ),
            "invalid_grant"
        );
        self.credentials.issue_oauth(
            p.name.unwrap(),
            p.approval.permissions,
            client_id.to_string(),
            self.issuer.clone(),
        )
    }
}
