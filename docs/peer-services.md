# Dynamic local applications (Linux)

Both `wayfinder daemon` and a daemon started by `wayfinder tui` automatically
expose a generic Unix domain socket. Applications discover it, register while
running, and reconnect when the daemon restarts. No application configuration,
service catalogue, descriptor file or daemon restart is needed to install an app.

## Discovery and authorization

The installed machine-wide endpoint is `/run/wayfinder/app.sock`. Its directory
is owned by the daemon account and the generic `wayfinder-apps` group, mode 2750;
the socket inherits that group and has mode 0660. Applications run as separate
accounts with supplementary membership in `wayfinder-apps`. Linux checks socket
write permission against the connecting process's credentials, including its
supplementary groups. Wayfinder records the peer UID alongside the random session
identity. No account-database lookup or per-application rule is needed.

Only the daemon can create/remove entries in the endpoint directory. Application
group members cannot replace the socket or impersonate the daemon there. Clients
should validate directory/socket ownership and restrictive modes, then verify
that SO_PEERCRED identifies the directory owner. Endpoint discovery reads no
private state. A directory lock prevents simultaneous daemon ownership; stale
sockets are removed only after acquiring it.

`wayfinder-service.sh install` (and `update`) creates `wayfinder-apps` and uses
systemd `RuntimeDirectory=wayfinder`, `RuntimeDirectoryMode=2750`, and
`Group=wayfinder-apps`. Private state remains mode 0700 with files 0600 and umask
0077; group membership grants no access to it. The installer retains the repository
owner as its service account; provision the checkout for the intended daemon
account before installation. Keep the daemon and applications
under distinct UIDs when isolation matters. Do not grant application accounts the
daemon's UID, private directories, administrative descriptors or credentials.

An application service installer can provision the generic group if absent and
use `SupplementaryGroups=wayfinder-apps`. For an interactive application account,
the one-time OS provisioning is `sudo usermod -aG wayfinder-apps APP_USER`, followed
by a new login. Group removal takes effect for new processes: stop existing
application processes/sessions when revoking access. All authorized applications
share the same limited interface; this is not isolation between group members.

For manual source use without systemd, provision the endpoint once per boot:

```sh
sudo groupadd --system wayfinder-apps # only if absent
sudo install -d -o WAYFINDER_USER -g wayfinder-apps -m 2750 /run/wayfinder
```

Alternatively, explicitly set `XDG_RUNTIME_DIR` for isolated development instances;
the endpoint is then `$XDG_RUNTIME_DIR/wayfinder/app.sock`. The runtime parent must
be owned by root or the daemon and not writable by others. A missing application
directory is created owner-only (0700, socket 0600), suitable for same-account
development. For separate-account development, provision that directory as 2750
with the generic access group and a traversable, protected runtime parent. Use
the same explicit runtime environment in daemon and application. Clients select
a provisioned `$XDG_RUNTIME_DIR/wayfinder` directory when present, otherwise the
machine endpoint; an ordinary login runtime directory alone does not override
the machine endpoint. This override
is generic OS environment, not application/service configuration.

The application API gives no access to private files, keys, membership
administration or command execution. It has a separate decoder and listener from
MCP, private administration and encrypted peer networking. No MCP bearer or admin
credential is provided or accepted. Linux is validated; other platforms keep
unrelated functionality but do not expose this dynamic application transport.

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
real-process validation (run as root to drop to distinct test UIDs) of encrypted
bidirectional echo, private-file denial, unauthorized-UID denial, third-node absence,
registration ownership, crash/restart cleanup, reconnection and API separation.

### Separate-account validation (2026-09-14)

The real-process suite passed 51 assertions with daemon UID 61001, application
UID 61002 and supplementary application GID 61003. UID 61004 without that group
was denied. No mount namespace concealed private state. Tests confirmed all four
private files remain 0600 behind a 0700 directory and cannot be read by the
application UID. Application connections exercised sanitized observation,
arbitrary registration, encrypted bidirectional echo, exact targeting, forbidden
operation rejection, separate MCP/admin credentials, ownership, crash cleanup,
application restart and daemon restart recovery. Root runs the test driver only
to provision and drop credentials; connection file descriptors are established
by the application UID before being handed to the driver.

Workspace formatting/check/Clippy/tests passed. A transient systemd unit also
verified 2750 runtime-directory permissions and inherited socket group under a
0077 umask. These are real linked processes on one Linux host, not a claimed
physical multi-machine test.
