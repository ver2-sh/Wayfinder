# Project Wayfinder

Wayfinder is a self-hosted Rust daemon that exposes two MCP tools: `nodes` and `exec`. Each installation executes commands as its own OS account and can route requests directly to linked Wayfinder nodes. Any member can be the MCP entry point. There is no permanent leader, web dashboard, cloud account, hosted relay, or telemetry.

```text
MCP client → authenticated MCP → selected Wayfinder node → fresh local shell
                                     │
                             authenticated Noise peers
                                     │
                         other Wayfinder nodes and shells

wayfinder tui → private loopback control API → daemon
```

Local applications expose [named private peer services](docs/peer-services.md)
through the automatic Linux Unix socket or Windows named pipe. Live sessions register arbitrary
service names; no application-specific setup or descriptor file is required.
Applications list generic nodes and open a named service on an exact stable node
ID over the existing authenticated Noise transport. Registration disappears on
session disconnect. Applications reconnect after daemon restart. Streams retain
bounded buffers, backpressure and cancellation, without retry or failover.

This grants arbitrary shell access as the daemon's account. It is not a sandbox. Use a dedicated, least-privileged OS account with only the files and network access you intend to grant. A command can read anything that account can read, including Wayfinder's own private files; credential separation does not protect against an authorized shell client or a compromised member.

## Build and run

Use a current stable Rust toolchain and Cargo. Linux is the validated platform; Unix process groups provide ordinary descendant cleanup. Dynamic local applications support Linux and native Windows 11 (no WSL); macOS remains unsupported for this interface. Windows applications run under the daemon account; see the [pipe ACL and native launch instructions](docs/peer-services.md#windows-discovery-and-authorization). Ubuntu and Windows use the same invitation and TCP/Noise peer network.

```sh
cargo build --release
cargo fmt --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Personal source-development endpoint (service installation uses /run/wayfinder).
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/wayfinder-$(id -u)}"
./target/release/wayfinder init --name server --mcp-enabled
./target/release/wayfinder daemon
```

Initialization prints the application-data directory. On Linux this defaults to `$XDG_DATA_HOME/wayfinder` or `~/.local/share/wayfinder`. Other platforms use their OS application-data location. All commands accept `--data-dir PATH` for an explicit private directory. No repository `.env` is read or required.

For interactive use, run under the same account:

```sh
./target/release/wayfinder tui
```

The TUI attaches to a live daemon for the selected data directory, or automatically starts a temporary daemon if none is running. `Q`, Ctrl+C, normal exit, and handled errors restore the terminal and stop only a daemon started by this TUI. An independently running daemon remains running. `wayfinder daemon` explicitly runs the persistent foreground daemon; use it under your OS service supervisor for unattended operation. A daemon holds an exclusive directory lock; two daemons cannot share one identity directory. SIGINT/SIGTERM shut down its listeners and cancel commands.

## Link machines

All members must have directly reachable advertised peer addresses. No NAT traversal, automatic discovery, VPN, or relay is included. Noise encrypts linking and permanent peer traffic; peer endpoints are IP addresses with ports, including bracketed IPv6.

Initialize each machine with its own **unique name**, directory, and identity. For example, on A:

```sh
wayfinder init --name server \
  --peer-listen 192.168.1.10:3001 \
  --peer-advertise 192.168.1.10:3001
wayfinder daemon
```

On B, use its own address and name:

```sh
wayfinder init --name storage \
  --peer-listen 192.168.1.11:3001 \
  --peer-advertise 192.168.1.11:3001
wayfinder daemon
```

MCP is disabled by default. Enable it only on desired entry nodes; its default address is `127.0.0.1:3000`. Permit the peer port between the intended machines.

1. Open A's TUI. Press `N`, enter a network name, and press Enter.
2. Press `A` to generate an invitation. Press `C` to copy it using the terminal's OSC 52 clipboard support. If the terminal does not permit clipboard access, use the private CLI operation below to obtain the single-line invitation.
3. Transfer the invitation privately to B. In B's TUI, press `J`, paste it, and press Enter. Wayfinder authenticates the introducing node against the invitation's key pin before displaying the discovered network and introducer.
4. Press `Y` to join. Within a few seconds both TUIs show the same membership. Each node's reachability observations may differ.
5. Add C through either member using the same workflow. Every member can introduce nodes; the creator has no special role.

Invitations contain a 256-bit one-use secret, network ID, introducing node identity/endpoint, and expiry. They expire in ten minutes, are consumed on successful membership admission, and are invalidated when the introducing daemon restarts. Generating a new invitation does not cancel older unexpired invitations. Invitations contain neither MCP credentials nor node private keys. Check clocks if an invitation is rejected as expired.

Use arrow keys and Enter for node details. `R` removes a selected remote node after `Y` confirmation. Remove this machine through another member. Removal revokes **future peer admission on members that know the removal**; it does not undo commands already accepted. Read the [consistency and revocation guarantees](docs/architecture.md#membership-consistency-and-revocation) before using removal across disconnected machines.

## MCP client setup

Enable `mcp_enabled` in `config.json` while stopped, or initialize a new node with
`--mcp-enabled`. Start the daemon, then create a client credential:

```sh
wayfinder auth create codex --permissions read,exec
wayfinder auth list
wayfinder auth revoke codex
```

Creation displays the token once. The default permission is **read only**. List
shows public metadata and Unix timestamps, never secrets or hashes. Revocation
applies to subsequent requests immediately; it does not undo admitted commands.
Use a new name for rotation, configure the replacement, then revoke the old name.

Configure a Streamable HTTP client with `http://127.0.0.1:3000/` locally, or your
HTTPS origin remotely, and `Authorization: Bearer <token>` on every request.
The [official Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk)
(`rmcp` 3.3.0, locked in Cargo.lock) owns protocol negotiation, initialization,
discovery, JSON/SSE responses and cancellation. The endpoint is **`/`**; `/mcp`
is removed. Local HTTP remains supported; there was no stdio MCP mode.

ChatGPT's developer-mode UI requires OAuth for authenticated connections.
Wayfinder also provides installation-local OAuth with PKCE, private CLI consent,
and the same credential store. See the complete [HTTPS and ChatGPT setup](docs/remote-mcp.md).

| Authority | Operations |
| --- | --- |
| `read` | MCP `nodes` |
| `exec` | MCP `exec`, local or across existing peers |
| Local administrator | Credential and network management through private control |

Capabilities are independent. There is no remotely grantable `admin` permission
or administrative MCP tool. An authorized shell still has the daemon account's
OS privileges, including access to its private files.

`nodes` returns stable IDs, unique names, the entry-node flag `local`, and `reachable` (last successful membership exchange). It does not disclose endpoints, peer keys, or secrets. Reachability is an observation, not a guarantee that the next request will succeed.

`exec` accepts:

| Field | Meaning |
| --- | --- |
| `command` | Required nonempty shell command, at most 64 KiB, no NUL |
| `target` | Optional stable node ID or unique name; omitted means the entry node |
| `cwd` | Optional working directory on the selected host |
| `timeout` | Optional milliseconds, 1–300000; default 30000 |
| `env` | Optional string map of environment overrides |

The result is both MCP `structuredContent` and matching JSON text:

```json
{
  "target": "<selected node's stable ID>",
  "stdout": "hello\n",
  "stderr": "",
  "exitCode": 0,
  "signal": null,
  "timedOut": false,
  "error": null
}
```

The shell is `/bin/sh -c` on Unix and `cmd.exe /D /S /C` on Windows. Stdin is closed, shells are fresh, and cwd/environment changes do not persist. The default cwd is the daemon's working directory. `WAYFINDER_*` environment variables from the launching process are excluded; explicit request overrides are still honored. Wayfinder does not place stored credentials or keys into its process environment.

Each output stream is buffered up to 1 MiB and decoded as UTF-8 with replacement for invalid bytes. Output overflow kills the process group and reports truncation. Timeouts, cancellation, spawn failures, nonzero exits and Unix signals remain explicit. MCP `isError` reflects unsuccessful results. Disconnecting a stateless HTTP request cancels its execution; a routed request closes its peer connection, which cancels the target command. Termination handles ordinary descendants, not deliberately detached processes. Forced daemon termination cannot guarantee cleanup.

There are at most 16 local executions and 64 inbound peer connections per node. Capacity exhaustion fails explicitly. Commands and output are not logged. There is no automatic retry or fallback. If a connection fails after dispatch, the execution outcome may be unknown: inspect the target before retrying an operation with side effects.

## Expose one MCP entry point

Use a reverse proxy to terminate HTTPS and forward to `127.0.0.1:3000`.
Wayfinder authenticates clients; the proxy preserves Authorization and rewrites
Host to loopback. Only MCP and OAuth routes are exposed. See the ingress example and operator
runbook in [docs/remote-mcp.md](docs/remote-mcp.md).

## Configuration and private control

`init` writes private `config.json`, `identity.json`, and `state.json`. The configuration has a version, node name, `mcp_enabled`, `mcp_listen`, optional `mcp_public_url`, `peer_listen`, and `peer_advertise`. No bearer secret is stored in configuration. The daemon owns private `credentials.json`, using the existing atomic JSON storage. Defaults are `127.0.0.1:3000` for MCP and `127.0.0.1:3001` for peers. Binding public or LAN interfaces requires explicit configuration. Peer encryption does not encrypt a directly exposed HTTP MCP listener.

Edit configuration only while that daemon is stopped. Restart to change listener configuration. Credentials are created/revoked live through the private API. For older unreleased configurations, remove `mcp_token` and add `mcp_enabled` and `mcp_public_url` while stopped; see the [existing-host cutover](docs/remote-mcp.md#existing-norted-host-cutover). Linked node names, peer keys and advertised endpoints are immutable in this first schema: remove the old node and initialize a fresh identity/directory for a changed descriptor. Do not copy an identity directory to another machine. Keep private backups; missing or malformed identity/state fails startup rather than silently replacing the node.

The daemon publishes `control.json` with an ephemeral loopback address and a separate random credential. The TUI reads this descriptor; it receives no execution/network managers. The descriptor is atomically replaced on startup and removed at graceful shutdown. The TUI verifies control API liveness; a stale descriptor after a crash does not count as a running daemon. MCP credentials cannot authorize control, and control credentials cannot authorize MCP. On Unix directories are mode 0700 and private files 0600; insecure file modes are rejected. Windows users must restrict the directory's ACL to the daemon account; Unix permission enforcement has no Windows equivalent here.

For terminal automation of **Wayfinder administration**, `status` and `control` use the same private API as the TUI. Control reads one operation from stdin; it has no shell-execution operation:

```sh
wayfinder status
printf '%s\n' '{"op":"create","name":"Home"}' | wayfinder control
printf '%s\n' '{"op":"invite","ttl":600}' | wayfinder control
```

Other operations are `details` (`id`), `preview` / `join` (`invitation`), and `remove` (`id`, `confirm: true`). Invitation-bearing JSON belongs on stdin, not in process arguments or shell history. The TUI provides the normal interactive workflow.

## Dedicated service account

Install the built binary somewhere the service account cannot modify, such as `/usr/local/bin/wayfinder`. Initialize its private application-data directory as that account. A minimal Linux systemd unit can use:

```ini
[Unit]
Description=Wayfinder node
After=network.target

[Service]
User=wayfinder
Group=wayfinder-apps
RuntimeDirectory=wayfinder
RuntimeDirectoryMode=2750
WorkingDirectory=/var/lib/wayfinder
ExecStart=/usr/local/bin/wayfinder --data-dir /var/lib/wayfinder daemon
Restart=on-failure
UMask=0077
KillMode=control-group

[Install]
WantedBy=multi-user.target
```

Create the generic `wayfinder-apps` group (see [local application access](docs/peer-services.md)). Provision `/var/lib/wayfinder` mode 0700 for that account and initialize it before starting the unit. Attach the TUI as the same account with the same `--data-dir`. Grant only intended OS permissions; do not run as root merely for convenience. The local supervisor controls Wayfinder's lifecycle; Wayfinder has no service-management API.

See [architecture and limitations](docs/architecture.md) and [validation record](docs/validation.md). Apache-2.0; see [LICENSE](LICENSE).
