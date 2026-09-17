//! Durable contracts and private, atomic local storage. No execution or transport.
use anyhow::{Context, Result, ensure};
use rand::{RngCore, rngs::OsRng};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

pub mod credentials;
pub mod oauth;
pub const VERSION: u32 = 1;
pub mod identity;
pub mod protocol;
pub mod security;
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
    let bytes = zeroize::Zeroizing::new(fs::read(path)?);
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
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(value)?);
        f.write_all(&bytes)?;
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
