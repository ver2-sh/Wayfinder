//! End-to-end coverage: real Unix endpoint, real self-hosted gateway, real
//! relay sockets, real Noise channels. Only loopback and temporary
//! directories are used; nothing touches installed services.
use super::*;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::{TcpListener, UnixStream};
use wayfinder_core::credentials::CredentialStore;
use wayfinder_core::identity::Role;

fn device(root: &ed25519_dalek::SigningKey, name: &str, issuer: &str) -> Installation {
    let key = new_key();
    let certificate = Certificate::issue(root, &key, name.into(), Role::Member).unwrap();
    Installation::new(issuer.into(), certificate, &key).unwrap()
}

async fn gateway(dir: &Path) -> Result<(Arc<CredentialStore>, String)> {
    let store = Arc::new(CredentialStore::open(dir.join("registry.sqlite"))?);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let issuer = format!("http://{}", listener.local_addr()?);
    let gateway = wayfinder_gateway::Gateway::new(issuer.clone(), store.clone())?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, gateway.router().into_make_service()).await;
    });
    Ok((store, issuer))
}

fn admit(
    store: &CredentialStore,
    root: &ed25519_dalek::SigningKey,
    i: &Installation,
    issuer: &str,
) {
    let nonce = random_secret();
    let signature = sign(
        root,
        &security::admission_proof(&i.certificate, issuer, &nonce).unwrap(),
    );
    store
        .admit(
            &security::Admission {
                certificate: i.certificate.clone(),
                nonce,
                signature,
            },
            issuer,
            now() + 30,
        )
        .unwrap();
}

/// Length-prefixed JSON local IPC, exactly the framing applications use.
async fn app_call(socket: &PathBuf, op: serde_json::Value) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(socket).await?;
    write_json(&mut stream, &op).await?;
    read_json(&mut stream).await
}

/// A registered backend: verifies the authenticated preface, then echoes.
async fn echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = async {
                    let preface: serde_json::Value = read_json(&mut stream).await?;
                    ensure!(
                        preface["credential"].as_str().is_some(),
                        "Missing credential"
                    );
                    write_json(&mut stream, &json!({"version":1,"ready":true})).await?;
                    let mut buf = vec![0; 8192];
                    loop {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 {
                            return Ok::<_, anyhow::Error>(());
                        }
                        stream.write_all(&buf[..n]).await?;
                    }
                }
                .await;
            });
        }
    });
    address
}

async fn wait_for(condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met in time");
}

#[tokio::test]
async fn local_endpoint_registers_and_opens_exact_device_services() {
    let dir = PathBuf::from(format!("/tmp/wf-e2e-{}", &random_secret()[..12]));
    let runtime = dir.join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    // SAFETY: the variable is read only by Endpoint::bind, called solely here.
    unsafe { std::env::set_var("XDG_RUNTIME_DIR", &runtime) };
    let (store, issuer) = gateway(&dir).await.unwrap();
    let root = new_key();
    let other_root = new_key();
    let ia = device(&root, "a", &issuer);
    let ib = device(&root, "b", &issuer);
    let id = device(&root, "d", &issuer);
    let ic = device(&other_root, "c", &issuer);
    for i in [&ia, &ib, &id] {
        admit(&store, &root, i, &issuer);
    }
    admit(&store, &other_root, &ic, &issuer);
    let apps_a = Arc::new(Apps::new(Arc::new(ia.clone())));
    let apps_b = Arc::new(Apps::new(Arc::new(ib.clone())));
    let (ia, ib) = (Arc::new(ia), Arc::new(ib));
    let stop = CancellationToken::new();
    // Only device A owns the local endpoint; B only takes relay sessions.
    {
        let apps = apps_a.clone();
        let stop = stop.child_token();
        tokio::spawn(async move { apps.serve(stop).await });
    }
    let path_a = dir.join("a");
    let path_b = dir.join("b");
    std::fs::create_dir_all(&path_a).unwrap();
    std::fs::create_dir_all(&path_b).unwrap();
    for (path, i, apps) in [
        (path_a.clone(), ia.clone(), apps_a.clone()),
        (path_b.clone(), ib.clone(), apps_b.clone()),
    ] {
        let stop = stop.child_token();
        tokio::spawn(async move { crate::session(&path, &i, &apps, stop).await });
    }
    let socket = runtime.join("wayfinder/app.sock");
    wait_for(|| socket.exists()).await;

    // Sanitized local status works with zero configuration.
    let status = app_call(&socket, json!({"op":"status"})).await.unwrap();
    let nodes = status["value"]["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|n| n["local"] == true));

    // Session-owned registration over the real socket, on device A.
    let credential_a = "a".repeat(64);
    let echo_a = echo_backend().await;
    let mut app_a = UnixStream::connect(&socket).await.unwrap();
    write_json(
        &mut app_a,
        &json!({"op":"register_service","service":"echo.a.v1","address":echo_a,"credential":credential_a}),
    )
    .await
    .unwrap();
    let reply: serde_json::Value = read_json(&mut app_a).await.unwrap();
    assert_eq!(reply["value"]["registered"], true);

    // Device B registers its own backend through its local registry.
    let credential_b = "b".repeat(64);
    let echo_b = echo_backend().await;
    apps_b
        .register_service("echo.b.v1".into(), echo_b, credential_b, "test".into())
        .await
        .unwrap();

    // Exact-target open A→B through the gateway, then an echo round trip.
    let target_b = bare_device_id(&ib.certificate.device_id);
    let mut opener = UnixStream::connect(&socket).await.unwrap();
    write_json(
        &mut opener,
        &json!({"op":"open_service","target":target_b,"service":"echo.b.v1"}),
    )
    .await
    .unwrap();
    let reply: serde_json::Value = read_json(&mut opener).await.unwrap();
    assert_eq!(reply, json!({"version":1,"ready":true}));
    opener.write_all(b"ping-wayfinder").await.unwrap();
    let mut echoed = vec![0; 14];
    tokio::time::timeout(Duration::from_secs(10), opener.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"ping-wayfinder");

    // EOF propagates: closing the application side ends the backend stream.
    opener.shutdown().await.unwrap();

    // Unknown service and offline/other-chain targets fail before dispatch.
    let unknown = app_call(
        &socket,
        json!({"op":"open_service","target":target_b,"service":"absent.v1"}),
    )
    .await
    .unwrap();
    assert!(
        unknown["error"]
            .as_str()
            .unwrap()
            .contains("not registered")
    );
    let offline = app_call(
        &socket,
        json!({"op":"open_service","target":bare_device_id(&id.certificate.device_id),"service":"echo.b.v1"}),
    )
    .await
    .unwrap();
    assert!(offline["error"].as_str().unwrap().contains("offline"));
    let foreign = app_call(
        &socket,
        json!({"op":"open_service","target":bare_device_id(&ic.certificate.device_id),"service":"echo.b.v1"}),
    )
    .await
    .unwrap();
    assert!(foreign["error"].as_str().is_some());

    // Opposite direction: B opens A's service over the same machinery.
    let channel = transport::open(&ib, &ia.certificate.device_id, "echo.a.v1")
        .await
        .unwrap();
    let (app_side, backend_side) = tokio::io::duplex(65536);
    let bridge = tokio::spawn(channel.bridge(backend_side));
    let (mut reader, mut writer) = tokio::io::split(app_side);
    writer.write_all(b"pong-wayfinder!").await.unwrap();
    let mut echoed = vec![0; 15];
    tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"pong-wayfinder!");
    writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), bridge).await;

    // Reconnect: B's session dies; opens fail; a fresh session recovers.
    stop.cancel();
    let opened_dead = transport::open(&ia, &ib.certificate.device_id, "echo.b.v1").await;
    assert!(
        opened_dead.is_err(),
        "offline target must fail before dispatch"
    );
    let stop2 = CancellationToken::new();
    {
        let apps = apps_a.clone();
        let stop = stop2.child_token();
        tokio::spawn(async move { apps.serve(stop).await });
    }
    for (path, i, apps) in [
        (path_b.clone(), ib.clone(), apps_b.clone()),
        (path_a.clone(), ia.clone(), apps_a.clone()),
    ] {
        let stop = stop2.child_token();
        tokio::spawn(async move { crate::session(&path, &i, &apps, stop).await });
    }
    // The application re-registers on the rebound endpoint, exactly as Scala
    // does on daemon restart; the registering session must stay alive.
    wait_for(|| socket.exists()).await;
    let mut app_a2 = UnixStream::connect(&socket).await.unwrap();
    write_json(
        &mut app_a2,
        &json!({"op":"register_service","service":"echo.a.v1","address":echo_a,"credential":credential_a}),
    )
    .await
    .unwrap();
    let reply: serde_json::Value = read_json(&mut app_a2).await.unwrap();
    assert_eq!(reply["value"]["registered"], true);
    let mut recovered = None;
    for _ in 0..200 {
        match transport::open(&ib, &ia.certificate.device_id, "echo.a.v1").await {
            Ok(channel) => {
                recovered = Some(channel);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    drop(recovered.expect("service transport did not recover after reconnect"));

    // Registrations are session-owned: a dead application session loses them.
    drop(app_a2);
    let apps = apps_a.clone();
    wait_for(|| !apps.services.lock().unwrap().contains_key("echo.a.v1")).await;

    stop2.cancel();
    let _ = std::fs::remove_dir_all(&dir);
}
