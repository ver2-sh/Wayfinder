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
through the automatic Unix application socket. Live sessions register arbitrary
service names; no application-specific setup or descriptor file is required.
Applications list generic nodes and open a named service on an exact stable node
ID over the existing authenticated Noise transport. Registration disappears on
session disconnect. Applications reconnect after daemon restart. Streams retain
bounded buffers, backpressure and cancellation, without retry or failover.

This grants arbitrary shell access as the daemon's account. It is not a sandbox. Use a dedicated, least-privileged OS account with only the files and network access you intend to grant. A command can read anything that account can read, including Wayfinder's own private files; credential separation does not protect against an authorized shell client or a compromised member.

## Build and run

Use a current stable Rust toolchain and Cargo. Linux is the validated platform; Unix process groups provide ordinary descendant cleanup. Dynamic local application transport is Linux-only in this iteration. Windows/macOS are unsupported for this interface.

```sh
cargo build --release
cargo fmt --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Personal source-development endpoint (service installation uses /run/wayfinder).
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/wayfinder-$(id -u)}"
./target/release/wayfinder init --name server
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

The MCP listener stays at `127.0.0.1:3000` on both machines. Permit the peer port between the intended machines.

1. Open A's TUI. Press `N`, enter a network name, and press Enter.
2. Press `A` to generate an invitation. Press `C` to copy it using the terminal's OSC 52 clipboard support. If the terminal does not permit clipboard access, use the private CLI operation below to obtain the single-line invitation.
3. Transfer the invitation privately to B. In B's TUI, press `J`, paste it, and press Enter. Wayfinder authenticates the introducing node against the invitation's key pin before displaying the discovered network and introducer.
4. Press `Y` to join. Within a few seconds both TUIs show the same membership. Each node's reachability observations may differ.
5. Add C through either member using the same workflow. Every member can introduce nodes; the creator has no special role.

Invitations contain a 256-bit one-use secret, network ID, introducing node identity/endpoint, and expiry. They expire in ten minutes, are consumed on successful membership admission, and are invalidated when the introducing daemon restarts. Generating a new invitation does not cancel older unexpired invitations. Invitations contain neither MCP credentials nor node private keys. Check clocks if an invitation is rejected as expired.

Use arrow keys and Enter for node details. `R` removes a selected remote node after `Y` confirmation. Remove this machine through another member. Removal revokes **future peer admission on members that know the removal**; it does not undo commands already accepted. Read the [consistency and revocation guarantees](docs/architecture.md#membership-consistency-and-revocation) before using removal across disconnected machines.

## MCP client setup

Explicitly obtain this node's MCP token for your client:

```sh
wayfinder token
```

Keep the output private. Configure a Streamable HTTP client with `http://127.0.0.1:3000/mcp` and `Authorization: Bearer <token>` on every request. The server uses the [official Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk), locked to the Cargo.lock dependency graph. The SDK handles initialization, tool discovery, protocol negotiation, JSON responses and SSE where required. This deployment uses stateless requests and configured bearer authentication, not OAuth discovery. Unknown paths, including OAuth discovery probes, return clean 404 responses before authentication.

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

Keep the backend on loopback and expose **only the chosen node's MCP endpoint** through HTTPS or an encrypted tunnel. The backend rejects browser Origin headers and validates Host to prevent DNS rebinding. The proxy must preserve Authorization and rewrite Host to the loopback backend. Do not inject a shared bearer at the proxy.

For example, with Caddy on that machine:

```caddyfile
wayfinder.example.com {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host 127.0.0.1:3000
    }
}
```

Use `https://wayfinder.example.com/mcp` in the client. Keep upstream response timeouts above 310 seconds and disable response buffering where necessary. A tunnel must provide encrypted remote transport and the same Host rewrite. Provider-specific tunnel credentials, organization/tenant selection, and control-plane authentication belong in that tunnel integration, not in Wayfinder; configure required provider context explicitly rather than relying on implicit account state. Never expose the private control listener. Other members' MCP ports do not need exposure; the selected gateway routes over authenticated Noise connections.

## Configuration and private control

`init` writes private `config.json`, `identity.json`, and `state.json`. The configuration has a version, node name, `mcp_listen`, `mcp_token`, `peer_listen`, and `peer_advertise`. Defaults are `127.0.0.1:3000` for MCP and `127.0.0.1:3001` for peers. Binding public or LAN interfaces requires explicit configuration. Peer encryption does not encrypt a directly exposed HTTP MCP listener.

Edit configuration only while that daemon is stopped. Restart to change MCP configuration or rotate its bearer. Linked node names, peer keys and advertised endpoints are immutable in this first schema: remove the old node and initialize a fresh identity/directory for a changed descriptor. Do not copy an identity directory to another machine. Keep private backups; missing or malformed identity/state fails startup rather than silently replacing the node.

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
