//! Chain-bound authorization code + S256 PKCE flow. Consent is granted
//! exclusively by an authenticated administrative device, never by possession of a browser URL.
use crate::{
    credentials::{Capability, CredentialStore, OAuthTokens},
    digest, now, random_secret,
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
    crate::identity::validate_gateway(value)?;
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
#[derive(Clone, Serialize, Deserialize)]
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
    chain: Option<String>,
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
    pub fn expire(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        state.pending.retain(|_, p| p.approval.expires > now());
        state.codes.retain(|_, c| c.expires > now());
        drop(state);
        self.credentials.expire_oauth()
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
        // Unapproved requests have their own budget and cannot consume the
        // slots reserved for chain-approved requests and authorization codes.
        if state.pending.values().filter(|p| p.chain.is_none()).count() >= 1024
            || state
                .pending
                .values()
                .filter(|p| p.approval.client_id == client.id && p.chain.is_none())
                .count()
                >= 4
        {
            return Err(failure("temporarily_unavailable"));
        }
        let ticket = random_secret();
        state.pending.insert(
            digest(ticket.as_bytes()),
            Pending {
                approval: Approval {
                    id: {
                        let s = random_secret();
                        format!("{}-{}", &s[..6], &s[6..12]).to_uppercase()
                    },
                    client_id: client.id,
                    client_name: client.name,
                    redirect_uri: client.redirect_uri,
                    permissions,
                    expires: now() + 600,
                },
                state: a.state,
                challenge: a.code_challenge,
                chain: None,
            },
        );
        Ok(ticket)
    }
    pub fn pending(&self, code: &str) -> Result<Approval> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        let matches: Vec<_> = state
            .pending
            .values()
            .filter(|p| p.approval.id == code && p.approval.expires > now() && p.chain.is_none())
            .collect();
        ensure!(
            matches.len() == 1,
            "Pending authorization not found or ambiguous"
        );
        Ok(matches[0].approval.clone())
    }
    pub fn approve(&self, code: &str, chain: String, request_hash: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("OAuth unavailable"))?;
        state.pending.retain(|_, p| p.approval.expires > now());
        state.codes.retain(|_, c| c.expires > now());
        let approved = state
            .pending
            .values()
            .filter_map(|p| p.chain.as_ref())
            .chain(
                state
                    .codes
                    .values()
                    .filter_map(|c| c.pending.chain.as_ref()),
            );
        ensure!(
            approved.clone().count() < 1024 && approved.filter(|c| **c == chain).count() < 16,
            "Approval capacity reached"
        );
        let matches = state
            .pending
            .values()
            .filter(|p| p.approval.id == code && p.approval.expires > now() && p.chain.is_none())
            .count();
        ensure!(matches == 1, "Pending authorization not found or ambiguous");
        let p = state
            .pending
            .values_mut()
            .find(|p| p.approval.id == code && p.approval.expires > now() && p.chain.is_none())
            .unwrap();
        ensure!(
            digest(&serde_json::to_vec(&p.approval)?) == request_hash,
            "Approval details changed"
        );
        p.chain = Some(chain);
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
        if p.chain.is_none() {
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
            p.chain.unwrap(),
            p.approval.client_name,
            p.approval.permissions,
            client_id.to_string(),
            self.issuer.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unapproved_flood_cannot_take_approved_capacity() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("wayfinder-flow-{}", random_secret()));
        let store = Arc::new(CredentialStore::open(dir.join("registry.sqlite"))?);
        let oauth = OAuth::new("http://127.0.0.1:12345".into(), store.clone())?;
        let register =
            || store.register_oauth_client("Test".into(), "http://127.0.0.1/callback".into(), true);
        let verifier = random_secret();
        let begin = |client: &crate::credentials::OAuthClientInfo| {
            oauth.begin(Authorization {
                response_type: "code".into(),
                client_id: client.id.clone(),
                redirect_uri: client.redirect_uri.clone(),
                scope: Some("read".into()),
                state: None,
                resource: oauth.issuer.clone(),
                code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                code_challenge_method: "S256".into(),
            })
        };
        let (client, _) = register()?;
        let ticket = begin(&client).map_err(|_| anyhow::anyhow!("begin failed"))?;
        for _ in 0..3 {
            assert!(begin(&client).is_ok());
        }
        assert!(begin(&client).is_err());
        for _ in 0..255 {
            let (c, _) = register()?;
            for _ in 0..4 {
                assert!(begin(&c).is_ok());
            }
        }
        let (other, _) = register()?;
        assert!(begin(&other).is_err());
        let approval = match oauth.continue_authorization(&ticket)? {
            Continue::Waiting(a) => a,
            _ => panic!("unexpected redirect"),
        };
        oauth.approve(
            &approval.id,
            "chain".into(),
            &digest(&serde_json::to_vec(&approval)?),
        )?;
        assert!(begin(&other).is_ok());
        assert!(matches!(
            oauth.continue_authorization(&ticket)?,
            Continue::Redirect(_)
        ));
        assert!(oauth.continue_authorization(&ticket).is_err());
        assert_eq!(oauth.state.lock().unwrap().codes.len(), 1);
        {
            let mut state = oauth.state.lock().unwrap();
            for p in state.pending.values_mut() {
                p.approval.expires = now();
            }
            for c in state.codes.values_mut() {
                c.expires = now();
            }
        }
        oauth.expire()?;
        assert!(oauth.state.lock().unwrap().pending.is_empty());
        assert!(oauth.state.lock().unwrap().codes.is_empty());
        assert!(begin(&other).is_ok());
        drop(oauth);
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    // Exercise expiry boundaries directly so validation never waits ten minutes
    // or changes the host clock. No production clock override exists.
    #[test]
    fn expired_pending_and_code_cannot_authorize() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("wayfinder-oauth-{}", random_secret()));
        let store = Arc::new(CredentialStore::open(dir.join("registry.sqlite"))?);
        let (client, _) = store.register_oauth_client(
            "Expiry test".into(),
            "http://127.0.0.1/callback".into(),
            true,
        )?;
        let oauth = OAuth::new("http://127.0.0.1:12345".into(), store.clone())?;
        let verifier = random_secret();
        let begin = || {
            oauth
                .begin(Authorization {
                    response_type: "code".into(),
                    client_id: client.id.clone(),
                    redirect_uri: client.redirect_uri.clone(),
                    scope: Some("read".into()),
                    state: Some("preserved".into()),
                    resource: oauth.issuer.clone(),
                    code_challenge: URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
                    code_challenge_method: "S256".into(),
                })
                .map_err(|_| anyhow::anyhow!("begin failed"))
        };
        let ticket = begin()?;
        let id = {
            let mut state = oauth.state.lock().unwrap();
            let pending = state.pending.get_mut(&digest(ticket.as_bytes())).unwrap();
            pending.approval.expires = now();
            pending.approval.id.clone()
        };
        assert!(oauth.pending(&id).is_err());
        assert!(oauth.approve(&id, "chain".into(), "hash").is_err());
        assert!(oauth.continue_authorization(&ticket).is_err());
        let ticket = begin()?;
        let approval = match oauth.continue_authorization(&ticket)? {
            Continue::Waiting(a) => a,
            _ => panic!("unapproved request redirected"),
        };
        oauth.approve(
            &approval.id,
            "chain".into(),
            &digest(&serde_json::to_vec(&approval)?),
        )?;
        let uri = match oauth.continue_authorization(&ticket)? {
            Continue::Redirect(u) => u,
            _ => panic!("approval did not redirect"),
        };
        let code = Url::parse(&uri)?
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        oauth
            .state
            .lock()
            .unwrap()
            .codes
            .get_mut(&digest(code.as_bytes()))
            .unwrap()
            .expires = now();
        assert!(
            oauth
                .exchange(
                    &code,
                    &client.id,
                    &client.redirect_uri,
                    &oauth.issuer,
                    &verifier
                )
                .is_err()
        );
        assert!(oauth.state.lock().unwrap().codes.is_empty());
        drop(oauth);
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
