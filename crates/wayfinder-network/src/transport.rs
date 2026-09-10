//! Length-bounded JSON messages inside authenticated Noise transport records.
use anyhow::{Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use snow::{HandshakeState, TransportState};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use wayfinder_core::{Identity, NOISE, PROLOGUE, key_bytes};
const MAX: usize = 16 * 1024 * 1024;
pub struct Channel {
    stream: TcpStream,
    noise: TransportState,
    pub remote: String,
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 65535, "Frame too large");
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let n = stream.read_u16().await? as usize;
    ensure!(n > 0, "Empty frame");
    let mut b = vec![0; n];
    stream.read_exact(&mut b).await?;
    Ok(b)
}
async fn send_handshake(s: &mut TcpStream, h: &mut HandshakeState) -> Result<()> {
    let mut b = [0; 65535];
    let n = h.write_message(&[], &mut b)?;
    write_frame(s, &b[..n]).await
}
async fn recv_handshake(s: &mut TcpStream, h: &mut HandshakeState) -> Result<()> {
    let b = read_frame(s).await?;
    let mut out = [0; 65535];
    h.read_message(&b, &mut out)?;
    Ok(())
}
impl Channel {
    pub async fn connect(
        endpoint: std::net::SocketAddr,
        expected: &str,
        identity: &Identity,
    ) -> Result<Self> {
        let s = TcpStream::connect(endpoint).await?;
        Self::handshake(s, identity, Some(expected)).await
    }
    pub async fn accept(s: TcpStream, identity: &Identity) -> Result<Self> {
        Self::handshake(s, identity, None).await
    }
    async fn handshake(
        mut stream: TcpStream,
        identity: &Identity,
        expected: Option<&str>,
    ) -> Result<Self> {
        stream.set_nodelay(true)?;
        let private = identity.noise_private()?;
        let builder = snow::Builder::new(NOISE.parse()?)
            .local_private_key(&private)?
            .prologue(PROLOGUE)?;
        let mut h = if expected.is_some() {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };
        if let Some(expected) = expected {
            send_handshake(&mut stream, &mut h).await?;
            recv_handshake(&mut stream, &mut h).await?;
            // Pin the inviter/peer before sending any application secret or request.
            ensure!(
                h.get_remote_static() == Some(key_bytes(expected)?.as_slice()),
                "Peer identity pin mismatch"
            );
            send_handshake(&mut stream, &mut h).await?;
        } else {
            recv_handshake(&mut stream, &mut h).await?;
            send_handshake(&mut stream, &mut h).await?;
            recv_handshake(&mut stream, &mut h).await?;
        }
        let remote = hex::encode(
            h.get_remote_static()
                .ok_or_else(|| anyhow::anyhow!("Missing peer identity"))?,
        );
        Ok(Self {
            stream,
            remote,
            noise: h.into_transport_mode()?,
        })
    }
    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() <= MAX, "Message too large");
        let mut plain = Vec::with_capacity(bytes.len() + 4);
        plain.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        plain.extend_from_slice(&bytes);
        let mut b = vec![0; 65535];
        for chunk in plain.chunks(60000) {
            let n = self.noise.write_message(chunk, &mut b)?;
            write_frame(&mut self.stream, &b[..n]).await?;
        }
        Ok(())
    }
    pub async fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut bytes = Vec::new();
        let mut expected = None;
        loop {
            let encrypted = read_frame(&mut self.stream).await?;
            let mut plain = vec![0; 65535];
            let n = self.noise.read_message(&encrypted, &mut plain)?;
            ensure!(n > 0, "Empty encrypted record");
            bytes.extend_from_slice(&plain[..n]);
            if expected.is_none() && bytes.len() >= 4 {
                let len = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
                ensure!(len <= MAX, "Message too large");
                expected = Some(len + 4);
            }
            if let Some(n) = expected {
                ensure!(bytes.len() <= n, "Invalid message framing");
                if bytes.len() == n {
                    return Ok(serde_json::from_slice(&bytes[4..])?);
                }
            }
        }
    }
    /// Any data or disconnect while an execution runs cancels that execution.
    pub async fn disconnected(&mut self) {
        let mut b = [0u8; 1];
        let _ = self.stream.read(&mut b).await;
    }
}
