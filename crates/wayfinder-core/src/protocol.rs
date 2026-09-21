use crate::{
    ExecInput, ExecResult,
    identity::{Certificate, field},
};
use serde::{Deserialize, Serialize};
/// Informational, self-reported connection metadata; not hardware attestation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformDescriptor {
    pub platform: String,
    pub arch: String,
}
impl PlatformDescriptor {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(
                self.platform.as_str(),
                "windows" | "linux" | "macos" | "other"
            ) && !self.arch.is_empty()
                && self.arch.len() <= 32
                && self
                    .arch
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "Invalid platform descriptor"
        );
        Ok(())
    }
}
pub const SESSION_VERSION: u32 = 2;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Challenge {
        version: u32,
        gateway: String,
        nonce: String,
    },
    Authenticate {
        certificate: Certificate,
        metadata: PlatformDescriptor,
        signature: String,
    },
    Ready,
    Exec {
        id: String,
        input: ExecInput,
    },
    Cancel {
        id: String,
    },
    Result {
        id: String,
        result: ExecResult,
    },
    Ping,
    Pong,
}
pub fn session_proof(
    gateway: &str,
    nonce: &str,
    cert: &Certificate,
    metadata: &PlatformDescriptor,
) -> anyhow::Result<Vec<u8>> {
    metadata.validate()?;
    let mut b = b"wayfinder/session/v2\0".to_vec();
    field(&mut b, gateway);
    field(&mut b, nonce);
    field(&mut b, &crate::digest(&cert.bytes()?));
    field(&mut b, &metadata.platform);
    field(&mut b, &metadata.arch);
    Ok(b)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Devices,
    RevokeDevice { device_id: String },
    Pending { code: String },
    Approve { code: String, request_hash: String },
    Grants,
    RevokeGrant { grant_id: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperation {
    pub certificate: Certificate,
    pub nonce: String,
    pub operation: Operation,
    pub signature: String,
}
pub fn operation_proof(
    gateway: &str,
    nonce: &str,
    cert: &Certificate,
    op: &Operation,
) -> anyhow::Result<Vec<u8>> {
    let mut b = b"wayfinder/administration/v1\0".to_vec();
    field(&mut b, gateway);
    field(&mut b, nonce);
    field(&mut b, &crate::digest(&cert.bytes()?));
    field(&mut b, &serde_json::to_string(op)?);
    Ok(b)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub role: crate::identity::Role,
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub last_seen: u64,
    pub revoked: bool,
    pub online: bool,
}
