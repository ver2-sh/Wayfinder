//! Durable contracts and private, atomic local storage. No execution or transport.
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub mod credentials;
pub mod oauth;
pub const VERSION: u32 = 1;
pub const NOISE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"wayfinder-peer-v1";
pub fn random_secret() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn secret_eq(a: &str, b: &str) -> bool {
    bool::from(Sha256::digest(a.as_bytes()).ct_eq(&Sha256::digest(b.as_bytes())))
}
pub fn bearer_value(header: &str) -> Option<&str> {
    let (scheme, value) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(value)
}
pub fn key_bytes(s: &str) -> Result<[u8; 32]> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "Keys and IDs require canonical lowercase hex"
    );
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))
}
pub fn valid_name(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.chars().all(|c| c.is_alphanumeric() || "-_. ".contains(c))
            && s.trim() == s,
        "Names must be 1–64 printable letters, numbers, spaces, -, _ or ."
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub name: String,
    pub mcp_listen: SocketAddr,
    pub peer_listen: SocketAddr,
    pub peer_advertise: SocketAddr,
    pub mcp_enabled: bool,
    pub mcp_public_url: Option<String>,
}
impl Config {
    pub fn new(
        name: String,
        mcp_listen: SocketAddr,
        peer_listen: SocketAddr,
        peer_advertise: SocketAddr,
    ) -> Result<Self> {
        let c = Self {
            version: VERSION,
            name,
            mcp_listen,
            peer_listen,
            peer_advertise,
            mcp_enabled: false,
            mcp_public_url: None,
        };
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == VERSION, "Unsupported config version");
        valid_name(&self.name)?;
        if let Some(issuer) = &self.mcp_public_url {
            oauth::validate_issuer(issuer)?;
        }
        ensure!(
            self.mcp_listen.port() != 0
                && self.peer_listen.port() != 0
                && self.peer_advertise.port() != 0
                && !self.peer_advertise.ip().is_unspecified(),
            "Listeners require nonzero ports and advertisement requires a reachable IP"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub version: u32,
    signing: String,
    noise_private: String,
    pub noise_public: String,
}
impl Identity {
    pub fn generate() -> Result<Self> {
        let kp = snow::Builder::new(NOISE.parse()?).generate_keypair()?;
        Ok(Self {
            version: VERSION,
            signing: random_secret(),
            noise_private: hex::encode(kp.private),
            noise_public: hex::encode(kp.public),
        })
    }
    pub fn signing(&self) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(&key_bytes(&self.signing)?))
    }
    pub fn noise_private(&self) -> Result<[u8; 32]> {
        key_bytes(&self.noise_private)
    }
    pub fn descriptor(&self, c: &Config) -> Result<Node> {
        ensure!(self.version == VERSION, "Unsupported identity version");
        use snow::resolvers::CryptoResolver;
        let mut dh = snow::resolvers::DefaultResolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .context("X25519 unavailable")?;
        dh.set(&self.noise_private()?);
        ensure!(
            dh.pubkey() == key_bytes(&self.noise_public)?.as_slice(),
            "Corrupt node identity: public/private peer keys differ"
        );
        Ok(Node {
            id: hex::encode(self.signing()?.verifying_key().as_bytes()),
            name: c.name.clone(),
            noise_key: self.noise_public.clone(),
            endpoint: c.peer_advertise,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub noise_key: String,
    pub endpoint: SocketAddr,
}
impl Node {
    pub fn validate(&self) -> Result<()> {
        valid_name(&self.name)?;
        VerifyingKey::from_bytes(&key_bytes(&self.id)?)?;
        key_bytes(&self.noise_key)?;
        ensure!(
            !self.endpoint.ip().is_unspecified() && self.endpoint.port() != 0,
            "Invalid peer endpoint"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub version: u32,
    pub network_id: String,
    pub name: String,
    pub parent: Option<String>,
    pub author: String,
    pub nodes: Vec<Node>,
    pub signature: String,
}
impl Revision {
    fn unsigned(&self) -> Result<Vec<u8>> {
        let mut r = self.clone();
        r.signature.clear();
        Ok(serde_json::to_vec(&r)?)
    }
    pub fn hash(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
    pub fn sign(
        network_id: String,
        name: String,
        parent: Option<String>,
        mut nodes: Vec<Node>,
        identity: &Identity,
    ) -> Result<Self> {
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        let key = identity.signing()?;
        let mut r = Self {
            version: VERSION,
            network_id,
            name,
            parent,
            author: hex::encode(key.verifying_key().as_bytes()),
            nodes,
            signature: String::new(),
        };
        r.signature = hex::encode(key.sign(&r.unsigned()?).to_bytes());
        Ok(r)
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub revisions: Vec<Revision>,
}
impl Membership {
    pub fn head(&self) -> Option<&Revision> {
        self.revisions.last()
    }
    pub fn nodes(&self) -> &[Node] {
        self.head().map(|r| r.nodes.as_slice()).unwrap_or(&[])
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            serde_json::to_vec(self)?.len() <= 8 * 1024 * 1024,
            "Membership history exceeds 8 MiB"
        );
        ensure!(
            self.revisions.len() <= 4096,
            "Membership history limit reached"
        );
        let mut prev: Option<&Revision> = None;
        for r in &self.revisions {
            ensure!(r.version == VERSION, "Unsupported membership version");
            key_bytes(&r.network_id)?;
            valid_name(&r.name)?;
            ensure!(
                !r.nodes.is_empty() && r.nodes.len() <= 128,
                "Network must contain 1–128 nodes"
            );
            let mut ids = BTreeSet::new();
            let mut names = BTreeSet::new();
            let mut keys = BTreeSet::new();
            for n in &r.nodes {
                n.validate()?;
                ensure!(
                    ids.insert(&n.id) && names.insert(&n.name) && keys.insert(&n.noise_key),
                    "Duplicate node identity, key or name"
                );
            }
            if let Some(p) = prev {
                ensure!(
                    r.parent.as_deref() == Some(p.hash()?.as_str())
                        && r.network_id == p.network_id
                        && r.name == p.name,
                    "Broken membership chain"
                );
                ensure!(
                    p.nodes.iter().any(|n| n.id == r.author),
                    "Membership author was not authorized"
                );
                // Each revision adds OR removes exactly one descriptor; retained identities cannot be rewritten.
                let removed: Vec<_> = p.nodes.iter().filter(|n| !r.nodes.contains(n)).collect();
                let added: Vec<_> = r.nodes.iter().filter(|n| !p.nodes.contains(n)).collect();
                ensure!(
                    removed.len() + added.len() == 1,
                    "Membership revision must add or remove exactly one node"
                );
            } else {
                ensure!(
                    r.parent.is_none() && r.nodes.len() == 1 && r.nodes[0].id == r.author,
                    "Invalid network genesis"
                );
            }
            ensure!(
                r.signature.len() == 128
                    && r.signature
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "Signature requires canonical lowercase hex"
            );
            let key = VerifyingKey::from_bytes(&key_bytes(&r.author)?)?;
            key.verify_strict(
                &r.unsigned()?,
                &Signature::from_slice(&hex::decode(&r.signature)?)?,
            )
            .context("Invalid membership signature")?;
            prev = Some(r);
        }
        Ok(())
    }
    pub fn extends(&self, other: &Self) -> bool {
        self.revisions.starts_with(&other.revisions)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persistent {
    pub version: u32,
    pub membership: Membership,
    pub conflict: bool,
}
impl Default for Persistent {
    fn default() -> Self {
        Self {
            version: VERSION,
            membership: Membership::default(),
            conflict: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecInput {
    pub target: Option<String>,
    pub command: String,
    pub cwd: Option<String>,
    pub timeout: Option<u64>,
    pub env: Option<BTreeMap<String, String>>,
}
impl ExecInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.command.trim().is_empty()
                && self.command.len() <= 65536
                && !self.command.contains('\0'),
            "Command must be nonempty, at most 64 KiB, without NUL"
        );
        ensure!(
            (1..=300_000).contains(&self.timeout.unwrap_or(30_000)),
            "Timeout must be 1–300000 ms"
        );
        if let Some(c) = &self.cwd {
            ensure!(!c.is_empty() && !c.contains('\0'), "Invalid cwd");
        }
        if let Some(e) = &self.env {
            for (k, v) in e {
                ensure!(
                    !k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0'),
                    "Invalid environment override"
                );
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub target: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out: bool,
    pub error: Option<String>,
}
impl ExecResult {
    pub fn empty(target: String) -> Self {
        Self {
            target,
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            signal: None,
            timed_out: false,
            error: None,
        }
    }
    pub fn failed(target: String, error: impl ToString) -> Self {
        Self {
            error: Some(error.to_string()),
            ..Self::empty(target)
        }
    }
    pub fn is_error(&self) -> bool {
        self.exit_code != Some(0) || self.timed_out || self.error.is_some()
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: String,
    pub name: String,
    pub local: bool,
    pub reachable: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
    pub node: Node,
    pub network_id: Option<String>,
    pub network_name: Option<String>,
    pub nodes: Vec<NodeStatus>,
    pub mcp_listen: SocketAddr,
    pub mcp_authenticated: bool,
    pub mcp_enabled: bool,
    pub peer_listen: SocketAddr,
    pub conflict: bool,
    pub revision: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDescriptor {
    pub version: u32,
    pub address: SocketAddr,
    pub credential: String,
}

pub fn default_data_dir() -> Result<PathBuf> {
    Ok(
        directories::ProjectDirs::from("org", "Wayfinder", "Wayfinder")
            .context("No application data directory")?
            .data_local_dir()
            .to_path_buf(),
    )
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub fn read_private<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= 16 * 1024 * 1024,
        "State must be a regular file of at most 16 MiB"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "Private file has insecure permissions: {}",
            path.display()
        );
    }
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= 16 * 1024 * 1024, "State too large");
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Malformed or unsupported local state"))
}
pub fn atomic_write<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("Missing parent directory")?;
    let temp = parent.join(format!(".{}.tmp", random_secret()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut f = options.open(&temp)?;
        f.write_all(&serde_json::to_vec_pretty(value)?)?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub fn lock_dir(path: &Path) -> Result<File> {
    private_dir(path)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let f = options.open(path.join("daemon.lock"))?;
    fs2::FileExt::try_lock_exclusive(&f).context("A daemon already owns this data directory")?;
    Ok(f)
}
pub fn load_or_create_identity(path: &Path) -> Result<Identity> {
    if path.exists() {
        read_private(path)
    } else {
        let i = Identity::generate()?;
        atomic_write(path, &i)?;
        Ok(i)
    }
}
pub fn load_state(path: &Path) -> Result<Persistent> {
    let s: Persistent = read_private(path)?;
    if s.version != VERSION {
        bail!("Unsupported state version");
    }
    s.membership.validate()?;
    Ok(s)
}
