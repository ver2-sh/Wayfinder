//! Fresh root-authorized admission prevents an old device certificate from
//! bootstrapping itself at a different or empty gateway.
use crate::identity::{Certificate, field, verify};
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub certificate: Certificate,
    pub nonce: String,
    pub signature: String,
}
pub fn admission_proof(c: &Certificate, gateway: &str, nonce: &str) -> Result<Vec<u8>> {
    let mut b = b"wayfinder/admission/v1\0".to_vec();
    field(&mut b, gateway);
    field(&mut b, nonce);
    field(&mut b, &crate::digest(&c.bytes()?));
    Ok(b)
}
impl Admission {
    pub fn verify(&self, gateway: &str) -> Result<()> {
        self.certificate.verify()?;
        verify(
            &self.certificate.root_public,
            &admission_proof(&self.certificate, gateway, &self.nonce)?,
            &self.signature,
        )
    }
}
