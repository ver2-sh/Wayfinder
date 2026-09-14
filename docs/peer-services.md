# Dynamic local applications (Linux)

Both `wayfinder daemon` and a daemon started by `wayfinder tui` automatically
expose a generic Unix domain socket. Applications discover it, register while
running, and reconnect when the daemon restarts. No application configuration,
service catalogue, descriptor file or daemon restart is needed to install an app.

## Discovery and authorization

The socket is `$XDG_RUNTIME_DIR/wayfinder/app.sock`. Without XDG_RUNTIME_DIR it is
`/run/user/<uid>/wayfinder/app.sock` when that user directory exists; otherwise it
is `/tmp/wayfinder-<uid>/wayfinder/app.sock`. The fallback is created automatically.
Applications and Wayfinder run under the same OS account and runtime environment.
A distinct XDG_RUNTIME_DIR can isolate multiple daemon instances for testing.
The socket location is independent of the private `--data-dir`.

The runtime parent must be owned by the daemon user and not writable by others.
The application directory is owner-only (0700), the socket is 0600, and accepted
connections must have the daemon's UID according to Unix peer credentials. A
separate directory lock prevents two daemons from claiming the same application
endpoint. Restart removes a stale socket only after acquiring that lock.

This is an OS-account boundary, not a sandbox between mutually hostile processes
sharing an account. The application API gives no access to private files, keys,
membership administration or command execution. It has a separate decoder and
listener from MCP, private administration and encrypted peer networking. No MCP
bearer or admin credential is provided or accepted. Linux is validated; dynamic
application transport on Windows/macOS is unsupported in this iteration.

## Wire contract

Each local request is a four-byte unsigned big-endian JSON byte length followed
by UTF-8 JSON (requests maximum 16 KiB, replies maximum 128 KiB). Unknown operations and unknown fields close the
session. The initial protocol is defined by these operations; admission replies
identify version 1. Requests are sequential on a session.

- `{"op":"status"}` returns `{"value":{"nodes":[{"id":"<full stable ID>",
  "name":"server","local":true,"reachable":true}],"conflict":false}}`.
  Nodes are machine membership, not application discovery. Local identity is the
  entry with `local: true`. No private identity or application metadata is returned.
- `{"op":"register_service","service":"echo.private.v1",
  "address":"127.0.0.1:49152","credential":"<64 hex characters>"}` returns
  `{"value":{"version":1,"registered":true}}`.
- `{"op":"unregister_service","service":"echo.private.v1"}` returns
  `{"value":{"unregistered":true}}`. Only the owning session may unregister.
- On a separate socket, `{"op":"open_service","target":"<full stable ID>",
  "service":"echo.private.v1"}` returns `{"version":1,"ready":true}`, then the
  socket becomes an application byte stream. A rejected open returns
  `{"error":"..."}` and closes. Other operation failures use the same error shape.

Service names are opaque: 1–96 lowercase ASCII letters, digits, dots, hyphens or
underscores. The application binds an ephemeral loopback listener and generates
its own random 256-bit hex credential internally. Neither is user configuration.
Applications may register multiple names. There are at most 32 registrations,
64 local sessions, and independently bounded encrypted service streams. Open
setup and reply writes have five-second deadlines; slow sessions cannot create
unbounded tasks or buffers. Applications should bound their own incoming work.

## Registration lifetime

A successful registration belongs to its live local socket session. Repeating
an identical registration on that session is harmless. Another session cannot
replace it, even with the same application credential. No registration is saved
or replicated. The TUI's Services view is read-only observation of live names.

When the application exits, crashes, explicitly unregisters, or closes the
session, its registrations are removed immediately when EOF is observed. There
is no lease or periodic renewal requirement. Keep the session open independently
of opened streams. Unregistration prevents new opens; already admitted streams
retain ordinary stream lifetime and cancellation semantics.

A daemon restart closes sessions and streams. Applications reconnect and register
again using their existing listener or a new ephemeral listener. The example
checks the session periodically to notice daemon loss; this is client liveness
observation, not registration renewal. Discovery may reconnect; application
operations must not be retried after possible dispatch.

## Peer transport

An open selects one exact current member by its full stable ID. Existing pinned
Noise encryption, membership authorization, conflict checks and service-name
routing apply. No peer application catalogue is distributed: clients try a named
service on nodes of interest, and service absence is an expected result.

The remote Wayfinder connects to the registered loopback address and sends a
framed JSON preface:

```json
{"version":1,"credential":"<application's registration credential>",
 "source":"<authenticated caller ID>","target":"<local ID>",
 "service":"echo.private.v1"}
```

The application verifies the credential, service and version and responds with
`{"version":1,"ready":true}` before any caller bytes are forwarded. Subsequent
bytes are opaque to Wayfinder. The encrypted bridge retains bounded 32 KiB
payload records, backpressure, cancellation and exact owner routing. EOF closes
both directions; truncated encrypted transport is an error. There is no automatic
retry, failover or stream resumption. Admin/MCP credentials remain independent.

## Runnable example and validation

After linking two machines normally, run `python3 examples/echo_app.py` beside
each daemon. It dynamically registers `echo.private.v1`, echoes bytes, and
reconnects automatically. Its socket helper and framing functions demonstrate
opening services without any private state access.

Run `cargo build -p wayfinder` then `python3 tests/dynamic_apps.py` for isolated
real-process validation of encrypted bidirectional echo, third-node absence,
registration ownership, crash/restart cleanup, reconnection and API separation.
