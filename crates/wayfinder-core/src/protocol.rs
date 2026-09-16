use crate::{
    ExecInput, ExecResult,
    identity::{Certificate, field},
};
use serde::{Deserialize, Serialize};
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
pub fn session_proof(gateway: &str, nonce: &str, cert: &Certificate) -> anyhow::Result<Vec<u8>> {
    let mut b = b"wayfinder/session/v1\0".to_vec();
    field(&mut b, gateway);
    field(&mut b, nonce);
    field(&mut b, &crate::digest(&cert.bytes()?));
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
    pub last_seen: u64,
    pub revoked: bool,
    pub online: bool,
}
