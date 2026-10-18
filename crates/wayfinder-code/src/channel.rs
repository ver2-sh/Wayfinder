//! A versioned release channel. The fixed HTTPS origin is the trust root.
//! The channel receives no device identity, credentials or project data.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
use wayfinder_core::digest;

pub const URL: &str = "https://usewayfinder.app/code-runtime/v1/stable.json";
pub const INTEGRATION: u32 = 1;
pub const MAX_BYTES: usize = 65536;
const EMBEDDED: &str = include_str!("../pins.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub url: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub schema: u32,
    pub revision: String,
    pub package_version: String,
    pub python: String,
    pub source: Artifact,
    pub uv_version: String,
    pub uv: BTreeMap<String, Artifact>,
    pub node_version: String,
    pub node: BTreeMap<String, Artifact>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub integration: u32,
    pub sequence: u64,
    pub pins: Pins,
}
pub fn embedded() -> Pins {
    serde_json::from_str(EMBEDDED).expect("repository-owned runtime pins")
}
pub fn hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_digit()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
}
impl Artifact {
    fn validate(&self, expected: &str) -> Result<()> {
        ensure!(
            self.url == expected && hex_id(&self.sha256, 64),
            "Invalid runtime artifact origin, path or integrity pin"
        );
        Ok(())
    }
}
impl Pins {
    pub fn id(&self) -> String {
        // Keep the install identity of the initial embedded recipe.
        if self == &embedded() {
            digest(EMBEDDED.as_bytes())
        } else {
            digest(&serde_json::to_vec(self).expect("serializable runtime pins"))
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1 && hex_id(&self.revision, 40),
            "Unsupported runtime recipe"
        );
        ensure!(
            version(&self.package_version)
                && version(&self.uv_version)
                && self.node_version.strip_prefix('v').is_some_and(version),
            "Runtime versions must be exact"
        );
        let python: Vec<_> = self.python.split('.').collect();
        ensure!(
            python.len() == 3
                && python[0] == "3"
                && python
                    .iter()
                    .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            "Python must have an exact major.minor.patch version"
        );
        self.source.validate(&format!(
            "https://codeload.github.com/oraios/serena/tar.gz/{}",
            self.revision
        ))?;
        ensure!(
            self.uv.len() == 6 && self.node.len() == 6,
            "Runtime recipe must cover the supported platforms"
        );
        for (platform, uv_target, node_target, extension) in [
            ("windows-x86_64", "x86_64-pc-windows-msvc", "win-x64", "zip"),
            (
                "windows-aarch64",
                "aarch64-pc-windows-msvc",
                "win-arm64",
                "zip",
            ),
            (
                "linux-x86_64",
                "x86_64-unknown-linux-gnu",
                "linux-x64",
                "tar.gz",
            ),
            (
                "linux-aarch64",
                "aarch64-unknown-linux-gnu",
                "linux-arm64",
                "tar.gz",
            ),
            (
                "macos-x86_64",
                "x86_64-apple-darwin",
                "darwin-x64",
                "tar.gz",
            ),
            (
                "macos-aarch64",
                "aarch64-apple-darwin",
                "darwin-arm64",
                "tar.gz",
            ),
        ] {
            let uv = self
                .uv
                .get(platform)
                .ok_or_else(|| anyhow::anyhow!("Missing bootstrap platform"))?;
            uv.validate(&format!(
                "https://github.com/astral-sh/uv/releases/download/{}/uv-{uv_target}.{extension}",
                self.uv_version
            ))?;
            let node = self
                .node
                .get(platform)
                .ok_or_else(|| anyhow::anyhow!("Missing Node.js platform"))?;
            node.validate(&format!(
                "https://nodejs.org/dist/{0}/node-{0}-{node_target}.{extension}",
                self.node_version
            ))?;
        }
        Ok(())
    }
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 1 && self.integration == INTEGRATION,
            "Code runtime update requires a different Wayfinder integration version"
        );
        ensure!(
            self.sequence > 0 && self.sequence <= 9_007_199_254_740_991,
            "Invalid release sequence"
        );
        self.pins.validate()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_BYTES,
            "Code runtime manifest exceeds limit"
        );
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
    pub fn id(&self) -> String {
        digest(&serde_json::to_vec(self).expect("serializable manifest"))
    }
}
pub async fn fetch() -> Result<Manifest> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client
        .get(URL)
        .header("User-Agent", "Wayfinder-code-runtime")
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.status().is_success(),
        "Code runtime channel redirects are not accepted"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BYTES as u64),
        "Code runtime manifest exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_BYTES,
            "Code runtime manifest exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Manifest::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_and_channel_have_the_same_install_identity() {
        let pins = embedded();
        pins.validate().unwrap();
        let manifest = Manifest {
            schema: 1,
            integration: INTEGRATION,
            sequence: 1,
            pins: pins.clone(),
        };
        let parsed = Manifest::decode(&serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
        assert_eq!(parsed.pins.id(), digest(EMBEDDED.as_bytes()));
    }
    #[test]
    fn rejects_unsafe_sources_unknown_fields_and_incompatible_versions() {
        let manifest = Manifest {
            schema: 1,
            integration: INTEGRATION,
            sequence: 1,
            pins: embedded(),
        };
        for field in ["schema", "integration"] {
            let mut value = serde_json::to_value(&manifest).unwrap();
            value[field] = 99.into();
            assert!(Manifest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["unexpected"] = true.into();
        assert!(Manifest::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        for url in [
            "http://codeload.github.com/oraios/serena/tar.gz/main",
            "https://attacker.invalid/archive",
            "https://codeload.github.com/other/repo/tar.gz/main",
        ] {
            let mut pins = embedded();
            pins.source.url = url.into();
            assert!(pins.validate().is_err());
        }
        let mut pins = embedded();
        pins.uv.values_mut().next().unwrap().url = "https://github.com/other/executable".into();
        assert!(pins.validate().is_err());
        let mut pins = embedded();
        pins.python = "3.13".into();
        assert!(pins.validate().is_err());
        let mut pins = embedded();
        pins.source.sha256 = "../outside".into();
        assert!(pins.validate().is_err());
        assert!(Manifest::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
