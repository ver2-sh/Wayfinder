use anyhow::Result;

/// Platforms without a local application transport expose no endpoint; the
/// daemon keeps running normally and binds nothing.
pub struct Endpoint;
impl Endpoint {
    pub fn bind() -> Result<Self> {
        anyhow::bail!("Local application transport requires Linux or Windows")
    }
    pub async fn accept(&mut self) -> Result<(tokio::io::DuplexStream, String)> {
        unreachable!()
    }
}
