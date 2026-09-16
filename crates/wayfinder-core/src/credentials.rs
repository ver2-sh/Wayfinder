//! Single-host SQLite registry. All device and grant administration is chain-scoped.
use crate::{digest, identity::Certificate, now, protocol::Device, random_secret, secret_eq};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Read,
    Exec,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub id: String,
    pub chain_id: String,
    pub name: String,
    pub client_id: String,
    pub permissions: BTreeSet<Capability>,
    pub created: u64,
    pub revoked: Option<u64>,
}
#[derive(Serialize)]
pub struct GrantInfo {
    #[serde(flatten)]
    pub identity: ClientIdentity,
    pub access_expires: u64,
    pub refresh_expires: u64,
    pub active: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthClientInfo {
    pub id: String,
    pub name: String,
    pub redirect_uri: String,
    pub public: bool,
}
#[derive(Serialize, Deserialize)]
struct Grant {
    identity: ClientIdentity,
    access_hash: String,
    refresh_hash: String,
    resource: String,
    expires: u64,
    refresh_expires: u64,
    used: BTreeSet<String>,
}
#[derive(Serialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}
struct Registration {
    info: OAuthClientInfo,
    secret_hash: Option<String>,
    expires: u64,
}
pub struct CredentialStore {
    registrations: Mutex<BTreeMap<String, Registration>>,
    admissions: Mutex<VecDeque<(Instant, String)>>,
    db: Mutex<Connection>,
}
impl CredentialStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        crate::private_dir(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("Missing database directory"))?,
        )?;
        if !path.exists() {
            let mut opts = std::fs::OpenOptions::new();
            opts.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&path)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::symlink_metadata(&path)?.is_file()
                    && std::fs::metadata(&path)?.permissions().mode() & 0o077 == 0,
                "Insecure database file"
            );
        }
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
  CREATE TABLE IF NOT EXISTS chains(id TEXT PRIMARY KEY, root TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS devices(chain TEXT NOT NULL REFERENCES chains(id), id TEXT NOT NULL, certificate TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL, PRIMARY KEY(chain,id));
  CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY, info TEXT NOT NULL, secret_hash TEXT);
  CREATE TABLE IF NOT EXISTS grants(chain TEXT NOT NULL REFERENCES chains(id), id TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(chain,id));
  CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, chain TEXT NOT NULL, grant_id TEXT NOT NULL, FOREIGN KEY(chain,grant_id) REFERENCES grants(chain,id));")?;
        Ok(Self {
            db: Mutex::new(db),
            registrations: Mutex::new(BTreeMap::new()),
            admissions: Mutex::new(VecDeque::new()),
        })
    }
    fn db(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow::anyhow!("Registry unavailable"))
    }
    pub fn register(&self, c: &Certificate) -> Result<()> {
        c.verify()?;
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO chains(id,root) VALUES(?1,?2)",
            params![c.chain_id, c.root_public],
        )?;
        let root: String =
            tx.query_row("SELECT root FROM chains WHERE id=?1", [&c.chain_id], |r| {
                r.get(0)
            })?;
        ensure!(root == c.root_public, "Root mismatch");
        let existing: Option<(String, bool)> = tx
            .query_row(
                "SELECT certificate,revoked FROM devices WHERE chain=?1 AND id=?2",
                params![c.chain_id, c.device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let cert = serde_json::to_string(c)?;
        if let Some((old, revoked)) = existing {
            ensure!(
                !revoked && old == cert,
                "Device revoked or certificate changed"
            );
            tx.execute(
                "UPDATE devices SET last_seen=?3 WHERE chain=?1 AND id=?2",
                params![c.chain_id, c.device_id, now()],
            )?;
        } else {
            // Rate-limit new durable trust state, never delete it to make room.
            // Existing devices reconnect and heartbeat without this admission budget.
            let mut admissions = self.admissions.lock().unwrap();
            while admissions
                .front()
                .is_some_and(|(t, _)| t.elapsed() >= Duration::from_secs(60))
            {
                admissions.pop_front();
            }
            ensure!(
                admissions.len() < 60
                    && admissions
                        .iter()
                        .filter(|(_, chain)| chain == &c.chain_id)
                        .count()
                        < 10,
                "New device admission rate exceeded; retry later"
            );
            admissions.push_back((Instant::now(), c.chain_id.clone()));
            tx.execute(
                "INSERT INTO devices(chain,id,certificate,last_seen) VALUES(?1,?2,?3,?4)",
                params![c.chain_id, c.device_id, cert, now()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn active(&self, c: &Certificate) -> Result<()> {
        let db = self.db()?;
        let valid: Option<(String, bool)> = db
            .query_row(
                "SELECT certificate,revoked FROM devices WHERE chain=?1 AND id=?2",
                params![c.chain_id, c.device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        ensure!(
            valid.is_some_and(|(cert, revoked)| !revoked
                && serde_json::from_str::<Certificate>(&cert).is_ok_and(|v| v == *c)),
            "Device is not active"
        );
        Ok(())
    }
    pub fn devices(&self, chain: &str) -> Result<Vec<Device>> {
        let db = self.db()?;
        let mut s = db.prepare(
            "SELECT certificate,revoked,last_seen FROM devices WHERE chain=?1 ORDER BY id",
        )?;
        let rows = s.query_map([chain], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, u64>(2)?,
            ))
        })?;
        let mut out = vec![];
        for r in rows {
            let (c, revoked, last_seen) = r?;
            let c: Certificate = serde_json::from_str(&c)?;
            out.push(Device {
                id: c.device_id,
                name: c.name,
                role: c.role,
                last_seen,
                revoked,
                online: false,
            });
        }
        Ok(out)
    }
    pub fn revoke_device(&self, chain: &str, id: &str) -> Result<()> {
        ensure!(
            self.db()?.execute(
                "UPDATE devices SET revoked=1 WHERE chain=?1 AND id=?2",
                params![chain, id]
            )? == 1,
            "Device not found"
        );
        Ok(())
    }
    pub fn list(&self, chain: &str) -> Result<Vec<GrantInfo>> {
        let db = self.db()?;
        let mut s = db.prepare("SELECT record FROM grants WHERE chain=?1")?;
        let rows = s.query_map([chain], |r| r.get::<_, String>(0))?;
        rows.map(|r| {
            let grant: Grant = serde_json::from_str(&r?)?;
            Ok(GrantInfo {
                active: grant.identity.revoked.is_none() && grant.refresh_expires > now(),
                access_expires: grant.expires,
                refresh_expires: grant.refresh_expires,
                identity: grant.identity,
            })
        })
        .collect()
    }
    pub fn revoke(&self, chain: &str, id: &str) -> Result<()> {
        let db = self.db()?;
        let raw: String = db.query_row(
            "SELECT record FROM grants WHERE chain=?1 AND id=?2",
            params![chain, id],
            |r| r.get(0),
        )?;
        let mut g: Grant = serde_json::from_str(&raw)?;
        g.identity.revoked = Some(now());
        db.execute(
            "UPDATE grants SET record=?3 WHERE chain=?1 AND id=?2",
            params![chain, id, serde_json::to_string(&g)?],
        )?;
        Ok(())
    }
    pub fn register_oauth_client(
        &self,
        name: String,
        redirect_uri: String,
        public: bool,
    ) -> Result<(OAuthClientInfo, String)> {
        crate::valid_name(&name)?;
        crate::oauth::validate_redirect(&redirect_uri)?;
        // Public DCR never writes durable rows. Only a chain-approved grant
        // promotes a registration to SQLite; abandoned registrations expire.
        let mut registrations = self.registrations.lock().unwrap();
        registrations.retain(|_, r| r.expires > now());
        ensure!(registrations.len() < 1024, "Registration capacity reached");
        let secret = random_secret();
        let c = OAuthClientInfo {
            id: random_secret(),
            name,
            redirect_uri,
            public,
        };
        registrations.insert(
            c.id.clone(),
            Registration {
                info: c.clone(),
                secret_hash: if public {
                    None
                } else {
                    Some(digest(secret.as_bytes()))
                },
                expires: now() + 3600,
            },
        );
        Ok((c, secret))
    }
    pub fn oauth_client(&self, id: &str, secret: Option<&str>) -> Result<OAuthClientInfo> {
        let (info, hash) = self.client_record(id)?;
        if let Some(secret) = secret {
            ensure!(
                hash.is_none() && secret.is_empty()
                    || hash.is_some_and(|h| secret_eq(&h, &digest(secret.as_bytes()))),
                "invalid_client"
            );
        }
        Ok(info)
    }
    fn client_record(&self, id: &str) -> Result<(OAuthClientInfo, Option<String>)> {
        {
            let registrations = self.registrations.lock().unwrap();
            if let Some(r) = registrations.get(id).filter(|r| r.expires > now()) {
                return Ok((r.info.clone(), r.secret_hash.clone()));
            }
        }
        let db = self.db()?;
        let (raw, hash): (String, Option<String>) = db.query_row(
            "SELECT info,secret_hash FROM clients WHERE id=?1 AND EXISTS (SELECT 1 FROM grants WHERE json_extract(record,'$.identity.client_id')=?1 AND json_extract(record,'$.refresh_expires')>?2)",
            params![id, now()], |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((serde_json::from_str(&raw)?, hash))
    }
    /// Expire only OAuth material whose absolute refresh lifetime has ended.
    /// Device rows, including revocation tombstones, are never collected.
    pub fn expire_oauth(&self) -> Result<()> {
        self.registrations
            .lock()
            .unwrap()
            .retain(|_, r| r.expires > now());
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute("DELETE FROM tokens WHERE EXISTS (SELECT 1 FROM grants g WHERE g.chain=tokens.chain AND g.id=tokens.grant_id AND json_extract(g.record,'$.refresh_expires')<=?1)", [now()])?;
        tx.execute(
            "DELETE FROM grants WHERE json_extract(record,'$.refresh_expires')<=?1",
            [now()],
        )?;
        tx.execute("DELETE FROM clients WHERE NOT EXISTS (SELECT 1 FROM grants WHERE json_extract(record,'$.identity.client_id')=clients.id)", [])?;
        tx.commit()?;
        Ok(())
    }
    pub fn issue_oauth(
        &self,
        chain: String,
        name: String,
        permissions: BTreeSet<Capability>,
        client_id: String,
        resource: String,
    ) -> Result<OAuthTokens> {
        let (client, secret_hash) = self.client_record(&client_id)?;
        ensure!(!permissions.is_empty(), "invalid_scope");
        let access = random_secret();
        let refresh = random_secret();
        let id = random_secret();
        let scope = crate::oauth::scope(&permissions);
        let g = Grant {
            identity: ClientIdentity {
                id: id.clone(),
                chain_id: chain.clone(),
                name,
                client_id,
                permissions,
                created: now(),
                revoked: None,
            },
            access_hash: digest(access.as_bytes()),
            refresh_hash: digest(refresh.as_bytes()),
            resource,
            expires: now() + 3600,
            refresh_expires: now() + 30 * 86400,
            used: BTreeSet::new(),
        };
        let mut db = self.db()?;
        let tx = db.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO clients VALUES(?1,?2,?3)",
            params![client.id, serde_json::to_string(&client)?, secret_hash],
        )?;
        tx.execute(
            "INSERT INTO grants VALUES(?1,?2,?3)",
            params![chain, id, serde_json::to_string(&g)?],
        )?;
        for token in [&access, &refresh] {
            tx.execute(
                "INSERT INTO tokens VALUES(?1,?2,?3)",
                params![digest(token.as_bytes()), chain, id],
            )?;
        }
        tx.commit()?;
        drop(db);
        self.registrations.lock().unwrap().remove(&client.id);
        Ok(OAuthTokens {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer",
            expires_in: 3600,
            scope,
        })
    }
    pub fn authenticate(&self, token: &str, issuer: &str) -> Result<Option<ClientIdentity>> {
        let db = self.db()?;
        let raw:Option<String>=db.query_row("SELECT g.record FROM tokens t JOIN grants g ON g.chain=t.chain AND g.id=t.grant_id WHERE t.hash=?1",[digest(token.as_bytes())],|r|r.get(0)).optional()?;
        let Some(raw) = raw else { return Ok(None) };
        let g: Grant = serde_json::from_str(&raw)?;
        Ok((secret_eq(&g.access_hash, &digest(token.as_bytes()))
            && g.identity.revoked.is_none()
            && g.expires > now()
            && g.resource == issuer)
            .then_some(g.identity))
    }
    pub fn refresh_oauth(
        &self,
        token: &str,
        client_id: &str,
        resource: &str,
        requested: Option<&str>,
    ) -> Result<OAuthTokens> {
        let mut db = self.db()?;
        let tx = db.transaction()?;
        let raw:String=tx.query_row("SELECT g.record FROM tokens t JOIN grants g ON g.chain=t.chain AND g.id=t.grant_id WHERE t.hash=?1",[digest(token.as_bytes())],|r|r.get(0))?;
        let mut g: Grant = serde_json::from_str(&raw)?;
        ensure!(
            g.identity.revoked.is_none()
                && g.identity.client_id == client_id
                && g.resource == resource
                && g.refresh_expires > now(),
            "invalid_grant"
        );
        let hash = digest(token.as_bytes());
        if g.used.contains(&hash) {
            g.identity.revoked = Some(now());
            tx.execute(
                "UPDATE grants SET record=?3 WHERE chain=?1 AND id=?2",
                params![
                    g.identity.chain_id,
                    g.identity.id,
                    serde_json::to_string(&g)?
                ],
            )?;
            tx.commit()?;
            anyhow::bail!("invalid_grant");
        }
        ensure!(
            secret_eq(&hash, &g.refresh_hash) && g.used.len() < 4096,
            "invalid_grant"
        );
        if let Some(s) = requested {
            let p = crate::oauth::permissions(s)?;
            ensure!(p.is_subset(&g.identity.permissions), "invalid_scope");
            g.identity.permissions = p;
        }
        let access = random_secret();
        let refresh = random_secret();
        tx.execute("DELETE FROM tokens WHERE hash=?1", [&g.access_hash])?;
        g.used.insert(hash);
        g.access_hash = digest(access.as_bytes());
        g.refresh_hash = digest(refresh.as_bytes());
        g.expires = (now() + 3600).min(g.refresh_expires);
        tx.execute(
            "UPDATE grants SET record=?3 WHERE chain=?1 AND id=?2",
            params![
                g.identity.chain_id,
                g.identity.id,
                serde_json::to_string(&g)?
            ],
        )?;
        for hash in [&g.access_hash, &g.refresh_hash] {
            tx.execute(
                "INSERT INTO tokens VALUES(?1,?2,?3)",
                params![hash, g.identity.chain_id, g.identity.id],
            )?;
        }
        tx.commit()?;
        Ok(OAuthTokens {
            access_token: access,
            refresh_token: refresh,
            token_type: "Bearer",
            expires_in: g.expires - now(),
            scope: crate::oauth::scope(&g.identity.permissions),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Role, new_key};
    #[test]
    fn public_registrations_expire_and_approved_clients_persist() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("wayfinder-registration-{}", random_secret()));
        let path = dir.join("registry.sqlite");
        let store = CredentialStore::open(path.clone())?;
        let cert = Certificate::issue(&new_key(), &new_key(), "Test".into(), Role::Admin)?;
        store.register(&cert)?;
        let register = || {
            store.register_oauth_client("Test".into(), "http://127.0.0.1/callback".into(), false)
        };
        let (abandoned, _) = register()?;
        store
            .registrations
            .lock()
            .unwrap()
            .get_mut(&abandoned.id)
            .unwrap()
            .expires = now();
        assert!(store.oauth_client(&abandoned.id, None).is_err());
        store.expire_oauth()?;
        assert!(store.registrations.lock().unwrap().is_empty());
        for _ in 0..1024 {
            register()?;
        }
        assert!(register().is_err());
        let count: u64 = store
            .db()?
            .query_row("SELECT count(*) FROM clients", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        for r in store.registrations.lock().unwrap().values_mut() {
            r.expires = now();
        }
        let (client, secret) = register()?;
        let tokens = store.issue_oauth(
            cert.chain_id.clone(),
            "Test".into(),
            BTreeSet::from([Capability::Read]),
            client.id.clone(),
            "http://127.0.0.1:12345".into(),
        )?;
        store.expire_oauth()?;
        assert!(store.oauth_client(&client.id, Some("wrong")).is_err());
        drop(store);
        let store = CredentialStore::open(path)?;
        assert!(store.oauth_client(&client.id, Some(&secret)).is_ok());
        let rotated = store.refresh_oauth(
            &tokens.refresh_token,
            &client.id,
            "http://127.0.0.1:12345",
            None,
        )?;
        store.expire_oauth()?;
        assert!(
            store
                .refresh_oauth(
                    &tokens.refresh_token,
                    &client.id,
                    "http://127.0.0.1:12345",
                    None
                )
                .is_err()
        );
        assert!(
            store
                .authenticate(&rotated.access_token, "http://127.0.0.1:12345")?
                .is_none()
        );
        store.revoke_device(&cert.chain_id, &cert.device_id)?;
        store.db()?.execute(
            "UPDATE grants SET record=json_set(record,'$.refresh_expires',?1)",
            [now()],
        )?;
        store.expire_oauth()?;
        assert!(store.oauth_client(&client.id, None).is_err());
        assert!(store.register(&cert).is_err());
        assert_eq!(store.devices(&cert.chain_id)?.len(), 1);
        let count: u64 = store
            .db()?
            .query_row("SELECT count(*) FROM tokens", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[test]
    fn admission_limits_only_new_devices_without_losing_tombstones() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("wayfinder-admission-{}", random_secret()));
        let store = CredentialStore::open(dir.join("registry.sqlite"))?;
        let root = new_key();
        let first = Certificate::issue(&root, &new_key(), "First".into(), Role::Admin)?;
        store.register(&first)?;
        for _ in 0..9 {
            store.register(&Certificate::issue(
                &root,
                &new_key(),
                "Other".into(),
                Role::Member,
            )?)?;
        }
        assert!(
            store
                .register(&Certificate::issue(
                    &root,
                    &new_key(),
                    "Excess".into(),
                    Role::Member
                )?)
                .is_err()
        );
        store.register(&first)?;
        let other = Certificate::issue(&new_key(), &new_key(), "Other chain".into(), Role::Admin)?;
        store.register(&other)?;
        store.revoke_device(&first.chain_id, &first.device_id)?;
        store.admissions.lock().unwrap().clear();
        assert!(store.register(&first).is_err());
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
