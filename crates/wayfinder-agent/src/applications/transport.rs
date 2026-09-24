//! Authenticated end-to-end encrypted service streams between two devices.
//!
//! Each open uses one dedicated `/service` relay WebSocket per side; the
//! gateway pairs them and forwards opaque binary records. Inside the relay the
//! agents run an ephemeral Noise NN handshake bound to the exact chain, stream,
//! source, target and service, then prove device identity with a certificate
//! and an Ed25519 signature over the handshake hash. The relay therefore only
//! ever sees ciphertext; it cannot read or forge application payloads.
use anyhow::{Context, Result, bail, ensure};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use wayfinder_core::{identity::*, protocol::*, *};

use crate::Socket;

const NOISE: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
const SETUP: Duration = Duration::from_secs(15);
/// An idle outbound direction emits an encrypted keepalive record so gateways
/// and NATs keep the relay socket alive. Records are indistinguishable from
/// data to the relay.
const KEEPALIVE: Duration = Duration::from_secs(20);
/// A stream with no inbound records at all for this long is dead.
const IDLE_LIMIT: Duration = Duration::from_secs(300);
/// One plaintext data record is at most 32 KiB plus its flag byte.
const CHUNK: usize = 32768;

/// A record-oriented sink: one Noise ciphertext record per call.
pub trait RecordSink: Send {
    fn send(&mut self, record: &[u8]) -> impl Future<Output = Result<()>> + Send;
}
/// A record-oriented source yielding exactly one record per call.
pub trait RecordStream: Send {
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

/// Writable half of an authenticated relay WebSocket.
pub struct RelaySink(pub SplitSink<Socket, Message>);
/// Readable half of an authenticated relay WebSocket.
pub struct RelayStream(pub SplitStream<Socket>);

impl RecordSink for RelaySink {
    fn send(&mut self, record: &[u8]) -> impl Future<Output = Result<()>> + Send {
        let message = (record.len() <= 65535).then(|| Message::Binary(record.to_vec().into()));
        async move {
            let message = message.ok_or_else(|| anyhow::anyhow!("Service record too large"))?;
            Ok(tokio::time::timeout(SETUP, self.0.send(message)).await??)
        }
    }
}
impl RecordStream for RelayStream {
    async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(b))) => {
                    ensure!(b.len() <= 65535, "Service record too large");
                    return Ok(b.to_vec());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                _ => bail!("Relay disconnected"),
            }
        }
    }
}

/// Signed proof that the channel peer owns the presented device certificate,
/// bound to this exact Noise session and routing context.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerAuth {
    certificate: Certificate,
    signature: String,
}

fn context(chain: &str, id: &str, source: &str, target: &str, service: &str) -> Vec<u8> {
    let mut b = b"wayfinder/service/v1\0".to_vec();
    for value in [chain, id, source, target, service] {
        field(&mut b, value);
    }
    b
}

fn auth_proof(context: &[u8], handshake_hash: &[u8]) -> Vec<u8> {
    let mut b = b"wayfinder/service-auth/v1\0".to_vec();
    b.extend_from_slice(context);
    b.extend_from_slice(handshake_hash);
    b
}

async fn send_auth<S: RecordSink, R: RecordStream>(
    link: &mut (S, R),
    noise: &mut snow::TransportState,
    auth: &PeerAuth,
) -> Result<()> {
    let payload = serde_json::to_vec(auth)?;
    ensure!(payload.len() <= 8192, "Peer authentication too large");
    let mut encrypted = vec![0; 65535];
    let n = noise.write_message(&payload, &mut encrypted)?;
    link.0.send(&encrypted[..n]).await
}

async fn receive_auth<S: RecordSink, R: RecordStream>(
    link: &mut (S, R),
    noise: &mut snow::TransportState,
) -> Result<PeerAuth> {
    let record = link.1.recv().await?;
    let mut plain = vec![0; 65535];
    let n = noise.read_message(&record, &mut plain)?;
    ensure!(n <= 8192, "Peer authentication too large");
    Ok(serde_json::from_slice(&plain[..n])?)
}

fn verify_peer(auth: &PeerAuth, own: &Installation, expected: &str, proof: &[u8]) -> Result<()> {
    auth.certificate.verify()?;
    ensure!(
        auth.certificate.device_id == expected
            && auth.certificate.chain_id == own.certificate.chain_id,
        "Service peer is not the authenticated target device"
    );
    verify(&auth.certificate.device_public, proof, &auth.signature)
}

/// An established end-to-end channel: ciphertext records on the relay,
/// plaintext bytes toward the local application or registered backend.
pub struct Channel<S, R> {
    sink: S,
    stream: R,
    noise: Arc<Mutex<snow::TransportState>>,
}

impl<S: RecordSink, R: RecordStream> Channel<S, R> {
    async fn establish(
        mut link: (S, R),
        i: &Installation,
        initiator: bool,
        expected: &str,
        context: &[u8],
    ) -> Result<Self> {
        let builder = snow::Builder::new(NOISE.parse()?).prologue(context);
        let mut h = if initiator {
            builder.build_initiator()?
        } else {
            builder.build_responder()?
        };
        let mut scratch = vec![0; 65535];
        if initiator {
            let n = h.write_message(&[], &mut scratch)?;
            link.0.send(&scratch[..n]).await?;
            let record = link.1.recv().await?;
            h.read_message(&record, &mut scratch)?;
        } else {
            let record = link.1.recv().await?;
            h.read_message(&record, &mut scratch)?;
            let n = h.write_message(&[], &mut scratch)?;
            link.0.send(&scratch[..n]).await?;
        }
        ensure!(h.is_handshake_finished(), "Incomplete service handshake");
        let hash = h.get_handshake_hash().to_vec();
        let mut noise = h.into_transport_mode()?;
        let proof = auth_proof(context, &hash);
        let mine = PeerAuth {
            certificate: i.certificate.clone(),
            signature: sign(&i.key()?, &proof),
        };
        let peer = if initiator {
            send_auth(&mut link, &mut noise, &mine).await?;
            receive_auth(&mut link, &mut noise).await?
        } else {
            let peer = receive_auth(&mut link, &mut noise).await?;
            send_auth(&mut link, &mut noise, &mine).await?;
            peer
        };
        verify_peer(&peer, i, expected, &proof)?;
        Ok(Self {
            sink: link.0,
            stream: link.1,
            noise: Arc::new(Mutex::new(noise)),
        })
    }

    /// Bridge a local byte stream to the encrypted channel. Record flags:
    /// 0 = data, 1 = end of stream, 2 = keepalive. EOF closes both directions;
    /// a truncated record flow is an error, not a clean EOF.
    pub async fn bridge<L: AsyncRead + AsyncWrite + Unpin>(self, local: L) -> Result<()> {
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let Self {
            mut sink,
            mut stream,
            noise,
        } = self;
        let writer = noise.clone();
        let send = async move {
            let mut plain = vec![0; CHUNK + 1];
            let mut encrypted = vec![0; 65535];
            loop {
                let n =
                    match tokio::time::timeout(KEEPALIVE, local_read.read(&mut plain[1..])).await {
                        Ok(read) => read?,
                        Err(_) => {
                            plain[0] = 2;
                            let len = writer
                                .lock()
                                .map_err(|_| anyhow::anyhow!("Cipher lock poisoned"))?
                                .write_message(&plain[..1], &mut encrypted)?;
                            sink.send(&encrypted[..len]).await?;
                            continue;
                        }
                    };
                plain[0] = u8::from(n == 0);
                let len = writer
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Cipher lock poisoned"))?
                    .write_message(&plain[..n + 1], &mut encrypted)?;
                sink.send(&encrypted[..len]).await?;
                if n == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        };
        let receive = async move {
            let mut plain = vec![0; 65535];
            loop {
                let record = tokio::time::timeout(IDLE_LIMIT, stream.recv())
                    .await
                    .context("Service stream idle limit reached")??;
                ensure!(record.len() <= 65535, "Service record too large");
                let n = noise
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Cipher lock poisoned"))?
                    .read_message(&record, &mut plain)?;
                match plain[0] {
                    0 if n > 1 => local_write.write_all(&plain[1..n]).await?,
                    1 if n == 1 => return Ok::<_, anyhow::Error>(()),
                    2 if n == 1 => continue,
                    _ => bail!("Invalid service record"),
                }
            }
        };
        tokio::select! { r = send => r, r = receive => r }
    }
}

/// The concrete channel over a paired relay WebSocket.
pub type RelayChannel = Channel<RelaySink, RelayStream>;

async fn send_control(sink: &mut SplitSink<Socket, Message>, frame: &Frame) -> Result<()> {
    tokio::time::timeout(
        SETUP,
        sink.send(Message::Text(serde_json::to_string(frame)?.into())),
    )
    .await??;
    Ok(())
}

/// Wait for the gateway's pairing verdict on a relay socket.
async fn await_pairing(stream: &mut SplitStream<Socket>, id: &str) -> Result<()> {
    loop {
        let frame: Frame = match stream.next().await {
            Some(Ok(Message::Text(t))) => {
                ensure!(t.len() <= 16384, "Relay control frame too large");
                serde_json::from_str(&t)?
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => bail!("Relay disconnected before pairing"),
        };
        match frame {
            Frame::ServiceReady { id: ready } if ready == id => return Ok(()),
            Frame::ServiceError { error, .. } => bail!("{error}"),
            _ => bail!("Unexpected relay control frame"),
        }
    }
}

/// Open a service stream to an exact device. Returns the established
/// end-to-end channel; fails cleanly before any application dispatch when the
/// target is offline, the service is unknown or the peer rejects admission.
pub async fn open(i: &Installation, target: &str, service: &str) -> Result<RelayChannel> {
    let socket = crate::connect_path(i, "service").await?;
    let (mut sink, mut stream) = socket.split();
    let id = random_secret();
    send_control(
        &mut sink,
        &Frame::ServiceOpen {
            version: SERVICE_VERSION,
            id: id.clone(),
            target: target.into(),
            service: service.into(),
        },
    )
    .await?;
    tokio::time::timeout(SETUP, await_pairing(&mut stream, &id))
        .await
        .context("Service open timed out before application dispatch")??;
    let context = context(
        &i.certificate.chain_id,
        &id,
        &i.certificate.device_id,
        target,
        service,
    );
    tokio::time::timeout(
        SETUP,
        Channel::establish(
            (RelaySink(sink), RelayStream(stream)),
            i,
            true,
            target,
            &context,
        ),
    )
    .await
    .context("Service authentication timed out")?
}

/// Accept an inbound service stream on a fresh relay socket. `id` is the
/// gateway stream identifier and `source` the full device ID of the opener.
pub async fn accept(
    i: &Installation,
    id: &str,
    source: &str,
    service: &str,
) -> Result<RelayChannel> {
    let socket = crate::connect_path(i, "service").await?;
    let (mut sink, mut stream) = socket.split();
    send_control(
        &mut sink,
        &Frame::ServiceAccept {
            version: SERVICE_VERSION,
            id: id.into(),
        },
    )
    .await?;
    tokio::time::timeout(SETUP, await_pairing(&mut stream, id))
        .await
        .context("Service accept timed out")??;
    let context = context(
        &i.certificate.chain_id,
        id,
        source,
        &i.certificate.device_id,
        service,
    );
    tokio::time::timeout(
        SETUP,
        Channel::establish(
            (RelaySink(sink), RelayStream(stream)),
            i,
            false,
            source,
            &context,
        ),
    )
    .await
    .context("Service authentication timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemSink(tokio::sync::mpsc::Sender<Vec<u8>>);
    struct MemStream(tokio::sync::mpsc::Receiver<Vec<u8>>);
    impl RecordSink for MemSink {
        async fn send(&mut self, record: &[u8]) -> Result<()> {
            Ok(self.0.send(record.to_vec()).await?)
        }
    }
    impl RecordStream for MemStream {
        async fn recv(&mut self) -> Result<Vec<u8>> {
            self.0
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Link closed"))
        }
    }
    fn link_pair() -> ((MemSink, MemStream), (MemSink, MemStream)) {
        let (a_tx, a_rx) = tokio::sync::mpsc::channel(8);
        let (b_tx, b_rx) = tokio::sync::mpsc::channel(8);
        (
            (MemSink(a_tx), MemStream(b_rx)),
            (MemSink(b_tx), MemStream(a_rx)),
        )
    }
    fn devices() -> (Installation, Installation) {
        let root = new_key();
        let ka = new_key();
        let kb = new_key();
        let ca = Certificate::issue(&root, &ka, "a".into(), Role::Admin).unwrap();
        let cb = Certificate::issue(&root, &kb, "b".into(), Role::Member).unwrap();
        (
            Installation::new("http://127.0.0.1:1".into(), ca, &ka).unwrap(),
            Installation::new("http://127.0.0.1:1".into(), cb, &kb).unwrap(),
        )
    }

    async fn channel_pair() -> (Channel<MemSink, MemStream>, Channel<MemSink, MemStream>) {
        let (a, b) = devices();
        let (la, lb) = link_pair();
        let id = "f".repeat(64);
        let service = "echo.private.v1";
        let ctx_a = context(
            &a.certificate.chain_id,
            &id,
            &a.certificate.device_id,
            &b.certificate.device_id,
            service,
        );
        let ctx_b = context(
            &b.certificate.chain_id,
            &id,
            &a.certificate.device_id,
            &b.certificate.device_id,
            service,
        );
        let (ai, bi) = (a.clone(), b.clone());
        let (ae, be) = (
            b.certificate.device_id.clone(),
            a.certificate.device_id.clone(),
        );
        let (x, y) = tokio::join!(
            Channel::establish(la, &ai, true, &ae, &ctx_a),
            Channel::establish(lb, &bi, false, &be, &ctx_b)
        );
        (x.unwrap(), y.unwrap())
    }

    #[tokio::test]
    async fn establish_only() {
        let _ = channel_pair().await;
    }

    #[tokio::test]
    async fn bridge_one_direction() {
        let (a, b) = channel_pair().await;
        let (a_app, a_backend) = tokio::io::duplex(65536);
        let (b_app, b_backend) = tokio::io::duplex(65536);
        tokio::spawn(a.bridge(a_backend));
        tokio::spawn(b.bridge(b_backend));
        let (_ar, mut aw) = tokio::io::split(a_app);
        let (mut br, _bw) = tokio::io::split(b_app);
        aw.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), br.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn mutual_authentication_and_application_bytes() {
        let (a, b) = channel_pair().await;
        let (a_app, a_backend) = tokio::io::duplex(65536);
        let (b_app, b_backend) = tokio::io::duplex(65536);
        let bridge_a = tokio::spawn(a.bridge(a_backend));
        let bridge_b = tokio::spawn(b.bridge(b_backend));
        let (mut ar, mut aw) = tokio::io::split(a_app);
        let (mut br, mut bw) = tokio::io::split(b_app);
        aw.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        br.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        bw.write_all(b"pong!").await.unwrap();
        let mut buf = [0u8; 5];
        ar.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong!");
        // Local shutdown propagates as an EOF record; the peer bridge ends and
        // closes its local side, then vice versa.
        aw.shutdown().await.unwrap();
        let mut end = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), br.read_to_end(&mut end))
            .await
            .unwrap()
            .unwrap();
        bridge_b.await.unwrap().unwrap();
        bw.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), ar.read_to_end(&mut Vec::new()))
            .await
            .unwrap()
            .unwrap();
        bridge_a.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wrong_expected_peer_is_rejected() {
        let (a, b) = devices();
        let (la, lb) = link_pair();
        let id = "e".repeat(64);
        let ctx_a = context(
            &a.certificate.chain_id,
            &id,
            &a.certificate.device_id,
            &b.certificate.device_id,
            "s.v1",
        );
        let ctx_b = context(
            &b.certificate.chain_id,
            &id,
            &a.certificate.device_id,
            &b.certificate.device_id,
            "s.v1",
        );
        // The responder expects a different source device than the real opener.
        let wrong = format!("wfd1_{}", "0".repeat(64));
        let (x, y) = tokio::join!(
            Channel::establish(la, &a, true, &b.certificate.device_id, &ctx_a),
            Channel::establish(lb, &b, false, &wrong, &ctx_b)
        );
        assert!(x.is_err() || y.is_err());
    }
}
