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

/// Version of the generic local application/service transport.
///
/// Service frames ride on the same authenticated session socket plus dedicated
/// authenticated `/service` relay sockets. Application payloads stay
/// end-to-end encrypted between the two Wayfinder agents and are opaque to
/// the gateway.
pub const SERVICE_VERSION: u32 = 1;

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
    Code {
        id: String,
        input: crate::code::CodeInput,
    },
    CodeResult {
        id: String,
        result: crate::code::CodeResult,
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
    /// Relay → gateway: open a service stream to an exact target device.
    ServiceOpen {
        version: u32,
        id: String,
        target: String,
        service: String,
    },
    /// Relay → gateway: accept a previously requested service stream.
    ServiceAccept {
        version: u32,
        id: String,
    },
    /// Gateway → relay: the stream is paired; end-to-end setup may start.
    ServiceReady {
        id: String,
    },
    /// Gateway → relay: the open failed before any dispatch.
    ServiceError {
        id: String,
        error: String,
    },
    /// Gateway → target agent control socket: a device wants a named service.
    ServiceRequest {
        version: u32,
        id: String,
        source: String,
        service: String,
    },
    /// Target agent → gateway: admission refused before the stream existed.
    ServiceReject {
        id: String,
        error: String,
    },
}

/// Opaque application service names such as `scala.link.v1`. They are routing
/// labels only; the gateway never learns a backend address, credential or
/// payload.
pub fn valid_service_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 96
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b)),
        "Invalid service name"
    );
    Ok(())
}

/// Full device IDs are `wfd1_` plus 64 lowercase hex characters.
pub fn valid_device_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        id.len() == 69 && id.starts_with("wfd1_") && id[5..].bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid device ID"
    );
    Ok(())
}

/// Local applications use the bare 64-hex node identity, without the `wfd1_`
/// prefix, matching the published Scala/Wayfinder IPC contract.
pub fn valid_node_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid node ID"
    );
    Ok(())
}

/// Strip the `wfd1_` prefix from a full device ID.
pub fn bare_device_id(id: &str) -> &str {
    id.strip_prefix("wfd1_").unwrap_or(id)
}

/// Accept either the bare node ID or the full `wfd1_` device ID and normalize
/// to the full form used internally and on the wire.
pub fn full_device_id(id: &str) -> anyhow::Result<String> {
    if valid_node_id(id).is_ok() {
        return Ok(format!("wfd1_{id}"));
    }
    valid_device_id(id)?;
    Ok(id.to_string())
}
pub fn session_proof(
    gateway: &str,
    nonce: &str,
    cert: &Certificate,
    metadata: &PlatformDescriptor,
) -> anyhow::Result<Vec<u8>> {
    session_proof_for(SESSION_VERSION, gateway, nonce, cert, metadata)
}
/// The negotiated protocol is authenticated, never inferred from an untrusted header.
pub fn session_proof_for(
    version: u32,
    gateway: &str,
    nonce: &str,
    cert: &Certificate,
    metadata: &PlatformDescriptor,
) -> anyhow::Result<Vec<u8>> {
    metadata.validate()?;
    let mut b = match version {
        SESSION_VERSION => b"wayfinder/session/v2\0".to_vec(),
        crate::code::CODE_SESSION_VERSION => b"wayfinder/session/v3\0".to_vec(),
        _ => anyhow::bail!("Unsupported agent protocol"),
    };
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
    PromoteDevice { device_id: String },
    DemoteDevice { device_id: String },
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
    if let Operation::PromoteDevice { device_id } | Operation::DemoteDevice { device_id } = op {
        let key = device_id
            .strip_prefix("wfd1_")
            .ok_or_else(|| anyhow::anyhow!("Invalid device ID"))?;
        crate::key_bytes(key)?;
    }
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
    /// Current gateway-local effective role.
    pub role: crate::identity::Role,
    /// Immutable root-signed role; absent on older gateways.
    #[serde(default)]
    pub certificate_role: Option<crate::identity::Role>,
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub last_seen: u64,
    pub revoked: bool,
    pub online: bool,
}

#[cfg(test)]
mod code_protocol_tests {
    use super::*;
    #[test]
    fn delegation_wire_vectors_match_typescript() -> anyhow::Result<()> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/protocol/fixtures/administration.json"
        ))?;
        let cert: Certificate = serde_json::from_value(fixture["certificate"].clone())?;
        cert.verify()?;
        for vector in fixture["vectors"].as_array().unwrap() {
            let op: Operation = serde_json::from_value(vector["operation"].clone())?;
            assert_eq!(
                serde_json::to_string(&op)?,
                vector["canonical"].as_str().unwrap()
            );
            let proof = operation_proof(
                fixture["gateway"].as_str().unwrap(),
                fixture["nonce"].as_str().unwrap(),
                &cert,
                &op,
            )?;
            assert_eq!(hex::encode(&proof), vector["proof"].as_str().unwrap());
            crate::identity::verify(
                &cert.device_public,
                &proof,
                vector["signature"].as_str().unwrap(),
            )?;
        }
        for invalid in [
            r#"{"operation":"promote_device"}"#,
            r#"{"operation":"demote_device","device_id":"x","extra":true}"#,
            r#"{"operation":"unknown_role","device_id":"x"}"#,
        ] {
            assert!(serde_json::from_str::<Operation>(invalid).is_err());
        }
        assert!(
            operation_proof(
                "gateway",
                "nonce",
                &cert,
                &Operation::PromoteDevice {
                    device_id: "invalid".into()
                }
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn code_capability_is_bound_to_the_signed_session_version() -> anyhow::Result<()> {
        let root = crate::identity::new_key();
        let device = crate::identity::new_key();
        let certificate =
            Certificate::issue(&root, &device, "test".into(), crate::identity::Role::Member)?;
        let metadata = PlatformDescriptor {
            platform: "windows".into(),
            arch: "x86_64".into(),
        };
        let old = session_proof("https://gateway.example", "nonce", &certificate, &metadata)?;
        let code = session_proof_for(
            crate::code::CODE_SESSION_VERSION,
            "https://gateway.example",
            "nonce",
            &certificate,
            &metadata,
        )?;
        assert!(old.starts_with(b"wayfinder/session/v2\0"));
        assert!(code.starts_with(b"wayfinder/session/v3\0"));
        assert_ne!(old, code);
        let signature = crate::identity::sign(&device, &old);
        assert!(crate::identity::verify(&certificate.device_public, &old, &signature).is_ok());
        assert!(crate::identity::verify(&certificate.device_public, &code, &signature).is_err());
        assert!(
            session_proof_for(
                999,
                "https://gateway.example",
                "nonce",
                &certificate,
                &metadata
            )
            .is_err()
        );
        Ok(())
    }
}
