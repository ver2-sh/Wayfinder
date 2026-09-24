//! Version 1 identity. Canonical signed bytes are fixed-width fields or length-prefixed UTF-8.
use crate::{digest, key_bytes, valid_name};
use anyhow::{Result, ensure};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;
pub const DEFAULT_GATEWAY: &str = "https://gateway.usewayfinder.app";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Member,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub version: u32,
    pub chain_id: String,
    pub root_public: String,
    pub device_id: String,
    pub device_public: String,
    pub role: Role,
    pub name: String,
    pub signature: String,
}
pub fn chain_id(public: &[u8; 32]) -> String {
    let mut b = b"wayfinder/chain-id/v1\0".to_vec();
    b.extend(public);
    format!("wfc1_{}", digest(&b))
}
pub fn device_id(public: &[u8; 32]) -> String {
    let mut b = b"wayfinder/device-id/v1\0".to_vec();
    b.extend(public);
    format!("wfd1_{}", digest(&b))
}
pub fn root(phrase: &str) -> Result<SigningKey> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|_| anyhow::anyhow!("Invalid 24-word English BIP39 phrase"))?;
    ensure!(mnemonic.word_count() == 24, "A 24-word phrase is required");
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let mut seed = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"wayfinder/sync-chain/v1"), &entropy)
        .expand(b"root-signing/ed25519", seed.as_mut())
        .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
    Ok(SigningKey::from_bytes(&seed))
}
pub fn new_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    SigningKey::from_bytes(&seed)
}
pub fn field(out: &mut Vec<u8>, s: &str) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend(s.as_bytes());
}
impl Certificate {
    pub fn issue(root: &SigningKey, device: &SigningKey, name: String, role: Role) -> Result<Self> {
        valid_name(&name)?;
        let r = root.verifying_key().to_bytes();
        let d = device.verifying_key().to_bytes();
        let mut c = Self {
            version: 1,
            chain_id: chain_id(&r),
            root_public: hex::encode(r),
            device_id: device_id(&d),
            device_public: hex::encode(d),
            role,
            name,
            signature: String::new(),
        };
        c.signature = hex::encode(root.sign(&c.bytes()?).to_bytes());
        Ok(c)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let mut b = b"wayfinder/membership/v1\0".to_vec();
        b.extend(self.version.to_be_bytes());
        field(&mut b, &self.chain_id);
        b.extend(key_bytes(&self.root_public)?);
        field(&mut b, &self.device_id);
        b.extend(key_bytes(&self.device_public)?);
        b.push(match self.role {
            Role::Admin => 1,
            Role::Member => 2,
        });
        field(&mut b, &self.name);
        Ok(b)
    }
    pub fn verify(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported certificate version");
        valid_name(&self.name)?;
        let r = key_bytes(&self.root_public)?;
        let d = key_bytes(&self.device_public)?;
        ensure!(
            self.chain_id == chain_id(&r) && self.device_id == device_id(&d),
            "Invalid identity binding"
        );
        verify(&self.root_public, &self.bytes()?, &self.signature)
    }
}
pub fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    hex::encode(key.sign(bytes).to_bytes())
}
pub fn verify(public: &str, bytes: &[u8], signature: &str) -> Result<()> {
    ensure!(
        signature.len() == 128
            && signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid signature encoding"
    );
    VerifyingKey::from_bytes(&key_bytes(public)?)?
        .verify_strict(bytes, &Signature::from_slice(&hex::decode(signature)?)?)
        .map_err(|_| anyhow::anyhow!("Invalid signature"))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub version: u32,
    pub gateway: String,
    pub certificate: Certificate,
    private_key: String,
}
impl Drop for Installation {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}
impl Installation {
    pub fn new(gateway: String, certificate: Certificate, key: &SigningKey) -> Result<Self> {
        validate_gateway(&gateway)?;
        Ok(Self {
            version: 1,
            gateway,
            certificate,
            private_key: hex::encode(Zeroizing::new(key.to_bytes()).as_slice()),
        })
    }
    pub fn key(&self) -> Result<SigningKey> {
        let bytes = Zeroizing::new(key_bytes(&self.private_key)?);
        Ok(SigningKey::from_bytes(&bytes))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported installation version");
        validate_gateway(&self.gateway)?;
        self.certificate.verify()?;
        ensure!(
            hex::encode(self.key()?.verifying_key().as_bytes()) == self.certificate.device_public,
            "Device key does not match membership"
        );
        Ok(())
    }
}
pub fn validate_gateway(value: &str) -> Result<()> {
    let u = url::Url::parse(value)?;
    ensure!(
        (u.scheme() == "https"
            || (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "[::1]"))))
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && u.path() == "/"
            && value == u.origin().ascii_serialization(),
        "Gateway must be a canonical HTTPS origin (HTTP allowed only for loopback testing)"
    );
    Ok(())
}
