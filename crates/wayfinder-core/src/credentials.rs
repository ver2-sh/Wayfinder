//! Installation-local API credentials, persisted using the existing private JSON store.
use crate::{atomic_write, digest, key_bytes, now, random_secret, read_private, valid_name};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf, sync::Mutex};
use subtle::ConstantTimeEq;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,
    Exec,
}

/// Public client identity; deliberately contains no verifier or bearer secret.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentity {
    pub id: String,
    pub name: String,
    pub permissions: BTreeSet<Capability>,
    pub created: u64,
    pub last_used: Option<u64>,
    pub revoked: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    client: ClientIdentity,
    secret_sha256: String,
    oauth: Option<OAuthGrant>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    version: u32,
    records: Vec<Record>,
    oauth_clients: Vec<OAuthClient>,
}
/// Owned by the daemon under its directory lock, shared only with ingress/control.
/// Never replicated to peers. Mutations commit before becoming visible in memory.
pub struct CredentialStore {
    path: PathBuf,
    state: Mutex<Credentials>,
}
impl CredentialStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        let state: Credentials = if path.exists() {
            read_private(&path)?
        } else {
            let empty = Credentials {
                version: 1,
                records: vec![],
                oauth_clients: vec![],
            };
            atomic_write(&path, &empty)?;
            empty
        };
        ensure!(
            state.version == 1 && state.records.len() <= 1024,
            "Unsupported credential store"
        );
        ensure!(
            state.oauth_clients.len() <= 128,
            "OAuth client limit exceeded"
        );
        let mut client_ids = BTreeSet::new();
        for c in &state.oauth_clients {
            key_bytes(&c.id)?;
            key_bytes(&c.secret_sha256)?;
            valid_name(&c.name)?;
            crate::oauth::validate_redirect(&c.redirect_uri)?;
            ensure!(client_ids.insert(&c.id), "Duplicate OAuth client");
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for r in &state.records {
            key_bytes(&r.client.id)?;
            key_bytes(&r.secret_sha256)?;
            valid_name(&r.client.name)?;
            if let Some(g) = &r.oauth {
                crate::oauth::validate_issuer(&g.resource)?;
                key_bytes(&g.refresh_sha256)?;
                ensure!(
                    client_ids.contains(&g.client_id) && g.used_refreshes.len() <= 4096,
                    "Invalid OAuth grant"
                );
                for hash in &g.used_refreshes {
                    key_bytes(hash)?;
                }
            }
            ensure!(
                !r.client.permissions.is_empty()
                    && ids.insert(&r.client.id)
                    && names.insert(&r.client.name),
                "Invalid credential record"
            );
        }
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }
    pub fn create(
        &self,
        name: String,
        permissions: BTreeSet<Capability>,
    ) -> Result<(ClientIdentity, String)> {
        valid_name(&name)?;
        ensure!(!permissions.is_empty(), "Select at least one permission");
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        ensure!(state.records.len() < 1024, "Credential limit reached");
        ensure!(
            !state.records.iter().any(|r| r.client.name == name),
            "Credential name already exists; choose a new name for rotation"
        );
        let client = ClientIdentity {
            id: random_secret(),
            name,
            permissions,
            created: now(),
            last_used: None,
            revoked: None,
        };
        let secret = random_secret();
        // 256 random bits from the OS CSPRNG make offline guessing infeasible.
        // SHA-256 is appropriate for this API secret, unlike a human password;
        // password KDF cost would only amplify unauthenticated request load.
        let mut updated = state.clone();
        updated.records.push(Record {
            client: client.clone(),
            secret_sha256: digest(secret.as_bytes()),
            oauth: None,
        });
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok((client.clone(), format!("wf_{}_{}", client.id, secret)))
    }
    pub fn list(&self) -> Result<Vec<ClientIdentity>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        Ok(state.records.iter().map(|r| r.client.clone()).collect())
    }
    pub fn revoke(&self, name: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        let mut updated = state.clone();
        let record = updated
            .records
            .iter_mut()
            .find(|r| r.client.name == name)
            .ok_or_else(|| anyhow::anyhow!("Credential not found"))?;
        record.client.revoked.get_or_insert_with(now);
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok(())
    }
    pub fn authenticate(
        &self,
        token: &str,
        issuer: Option<&str>,
    ) -> Result<Option<ClientIdentity>> {
        let Some((id, secret)) = token.strip_prefix("wf_").and_then(|v| v.split_once('_')) else {
            return Ok(None);
        };
        if key_bytes(id).is_err() || key_bytes(secret).is_err() {
            return Ok(None);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        let Some(index) = state.records.iter().position(|r| r.client.id == id) else {
            return Ok(None);
        };
        let record = &state.records[index];
        let supplied = digest(secret.as_bytes());
        if !bool::from(supplied.as_bytes().ct_eq(record.secret_sha256.as_bytes()))
            || record.client.revoked.is_some()
            || record
                .oauth
                .as_ref()
                .is_some_and(|g| Some(g.resource.as_str()) != issuer || now() >= g.expires)
        {
            return Ok(None);
        }
        // Persist at most once a minute per active credential, bounding write load.
        let used = now();
        if record
            .client
            .last_used
            .is_none_or(|last| used.saturating_sub(last) >= 60)
        {
            let mut updated = state.clone();
            updated.records[index].client.last_used = Some(used);
            atomic_write(&self.path, &updated)?;
            *state = updated;
        }
        Ok(Some(state.records[index].client.clone()))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthGrant {
    client_id: String,
    resource: String,
    expires: u64,
    refresh_expires: u64,
    refresh_sha256: String,
    used_refreshes: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthClient {
    revoked: Option<u64>,
    id: String,
    name: String,
    redirect_uri: String,
    secret_sha256: String,
}
#[derive(Clone, Serialize)]
pub struct OAuthClientInfo {
    pub revoked: Option<u64>,
    pub id: String,
    pub name: String,
    pub redirect_uri: String,
}
#[derive(Serialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}
impl CredentialStore {
    pub fn register_oauth_client(
        &self,
        name: String,
        redirect_uri: String,
    ) -> Result<(OAuthClientInfo, String)> {
        valid_name(&name)?;
        crate::oauth::validate_redirect(&redirect_uri)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        ensure!(
            state.oauth_clients.len() < 128 && !state.oauth_clients.iter().any(|c| c.name == name),
            "OAuth client limit or duplicate name"
        );
        let secret = random_secret();
        let client = OAuthClient {
            revoked: None,
            id: random_secret(),
            name,
            redirect_uri,
            secret_sha256: digest(secret.as_bytes()),
        };
        let info = OAuthClientInfo {
            revoked: client.revoked,
            id: client.id.clone(),
            name: client.name.clone(),
            redirect_uri: client.redirect_uri.clone(),
        };
        let mut updated = state.clone();
        updated.oauth_clients.push(client);
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok((info, secret))
    }
    pub fn oauth_client(&self, id: &str, secret: Option<&str>) -> Result<OAuthClientInfo> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        let c = state
            .oauth_clients
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("invalid_client"))?;
        if let Some(secret) = secret {
            ensure!(
                bool::from(
                    digest(secret.as_bytes())
                        .as_bytes()
                        .ct_eq(c.secret_sha256.as_bytes())
                ),
                "invalid_client"
            );
        }
        ensure!(c.revoked.is_none(), "invalid_client");
        Ok(OAuthClientInfo {
            revoked: c.revoked,
            id: c.id.clone(),
            name: c.name.clone(),
            redirect_uri: c.redirect_uri.clone(),
        })
    }
    pub fn issue_oauth(
        &self,
        name: String,
        permissions: BTreeSet<Capability>,
        client_id: String,
        resource: String,
    ) -> Result<OAuthTokens> {
        valid_name(&name)?;
        ensure!(!permissions.is_empty(), "Select permissions");
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        ensure!(
            state.records.len() < 1024 && !state.records.iter().any(|r| r.client.name == name),
            "Credential limit or duplicate name"
        );
        ensure!(
            state
                .oauth_clients
                .iter()
                .any(|c| c.id == client_id && c.revoked.is_none()),
            "invalid_client"
        );
        let id = random_secret();
        let secret = random_secret();
        let refresh = random_secret();
        let scope = crate::oauth::scope(&permissions);
        let record = Record {
            client: ClientIdentity {
                id: id.clone(),
                name,
                permissions,
                created: now(),
                last_used: None,
                revoked: None,
            },
            secret_sha256: digest(secret.as_bytes()),
            oauth: Some(OAuthGrant {
                client_id,
                resource,
                expires: now() + 3600,
                refresh_expires: now() + 30 * 86400,
                refresh_sha256: digest(refresh.as_bytes()),
                used_refreshes: BTreeSet::new(),
            }),
        };
        let mut updated = state.clone();
        updated.records.push(record);
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok(OAuthTokens {
            access_token: format!("wf_{id}_{secret}"),
            refresh_token: format!("wfr_{id}_{refresh}"),
            token_type: "Bearer",
            expires_in: 3600,
            scope,
        })
    }
    pub fn refresh_oauth(
        &self,
        token: &str,
        client_id: &str,
        resource: &str,
        requested_scope: Option<&str>,
    ) -> Result<OAuthTokens> {
        let (id, secret) = token
            .strip_prefix("wfr_")
            .and_then(|s| s.split_once('_'))
            .ok_or_else(|| anyhow::anyhow!("invalid_grant"))?;
        key_bytes(id)?;
        key_bytes(secret)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        let mut updated = state.clone();
        let r = updated
            .records
            .iter_mut()
            .find(|r| r.client.id == id)
            .ok_or_else(|| anyhow::anyhow!("invalid_grant"))?;
        let g = r
            .oauth
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid_grant"))?;
        ensure!(
            r.client.revoked.is_none()
                && g.client_id == client_id
                && g.resource == resource
                && now() < g.refresh_expires,
            "invalid_grant"
        );
        let supplied = digest(secret.as_bytes());
        if g.used_refreshes.contains(&supplied) {
            r.client.revoked = Some(now());
            atomic_write(&self.path, &updated)?;
            *state = updated;
            anyhow::bail!("invalid_grant");
        }
        ensure!(
            bool::from(supplied.as_bytes().ct_eq(g.refresh_sha256.as_bytes()))
                && g.used_refreshes.len() < 4096,
            "invalid_grant"
        );
        if let Some(requested) = requested_scope {
            let requested = crate::oauth::permissions(requested)?;
            ensure!(requested.is_subset(&r.client.permissions), "invalid_scope");
            r.client.permissions = requested;
        }
        let secret = random_secret();
        let refresh = random_secret();
        g.used_refreshes.insert(supplied);
        g.refresh_sha256 = digest(refresh.as_bytes());
        let expires_in = 3600.min(g.refresh_expires.saturating_sub(now()));
        g.expires = now() + expires_in;
        r.secret_sha256 = digest(secret.as_bytes());
        let scope = crate::oauth::scope(&r.client.permissions);
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok(OAuthTokens {
            access_token: format!("wf_{id}_{secret}"),
            refresh_token: format!("wfr_{id}_{refresh}"),
            token_type: "Bearer",
            expires_in,
            scope,
        })
    }
}

impl CredentialStore {
    pub fn oauth_clients(&self) -> Result<Vec<OAuthClientInfo>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        Ok(state
            .oauth_clients
            .iter()
            .map(|c| OAuthClientInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                redirect_uri: c.redirect_uri.clone(),
                revoked: c.revoked,
            })
            .collect())
    }
    pub fn revoke_oauth_client(&self, name: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Credential store unavailable"))?;
        let mut updated = state.clone();
        let c = updated
            .oauth_clients
            .iter_mut()
            .find(|c| c.name == name)
            .ok_or_else(|| anyhow::anyhow!("OAuth client not found"))?;
        c.revoked.get_or_insert_with(now);
        let id = c.id.clone();
        for r in &mut updated.records {
            if r.oauth.as_ref().is_some_and(|g| g.client_id == id) {
                r.client.revoked.get_or_insert_with(now);
            }
        }
        atomic_write(&self.path, &updated)?;
        *state = updated;
        Ok(())
    }
}
