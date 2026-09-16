# Wayfinder

Wayfinder is an accountless Sync Chain of devices that an MCP client can discover
and run shell commands on. Install the **agent** on each device. Every agent makes
an outbound encrypted connection to a gateway; no inbound device port, peer IP,
public hostname, VPN or personal MCP server is required.

The default gateway and MCP URL is **https://mcp.usewayfinder.app**. The same
open-source gateway can be self-hosted. No email, password or hosted account is
required. Apache-2.0 licensed; unreleased, with no legacy-state compatibility.

```text
ChatGPT / other MCP client ── HTTPS + chain-bound OAuth ──┐
                                                       v
                                    Wayfinder Gateway (MCP, OAuth, SQLite)
                                          ^            ^            ^
                                          | outbound WSS sessions    |
                                     Chain A       Chain A       Chain B
                                     device 1      device 2       device 1
```

## Install the agent

Requires Rust 1.88+ and a native build toolchain. Linux is exercised end-to-end;
the agent also contains Windows shell/process support and uses portable Rust
networking. Windows/macOS service packaging is not provided or validated here.

```sh
./build-production.sh
sudo install -m 0755 target/release/wayfinder /usr/local/bin/wayfinder
wayfinder chain create --name laptop
wayfinder daemon
```

Run creation in a **private, unrecorded interactive terminal**. It displays a
24-word BIP39 recovery phrase once, requires confirmation that it was saved, saves
only this device's identity, and registers with the gateway. If registration fails,
the identity remains saved: start `wayfinder daemon` to retry with that identity.
Never initialize repeatedly to resolve connection problems.

On another device:

```sh
wayfinder chain join --name workstation
wayfinder daemon
```

Join prompts for the phrase with terminal echo disabled. It reconstructs the same
Chain ID and generates an independent device key. Use `--admin` only when you want
that device to approve MCP clients and administer the chain. The creator is an
administrator; joins default to member. A root phrase holder can enroll admins.

For protected automation, `chain join --phrase-stdin` reads at most 1 KiB from a
pipe or redirected input. Do not put the phrase in shell commands, environment
variables, process arguments, browser pages, MCP clients, logs, or telemetry. Do
not type an `echo PHRASE | ...` command. Creation refuses redirected output.
Wayfinder does not persist the phrase/root secret and cannot show it again.
Memory containing transient phrases, entropy and signing seeds is zeroized where
practical; this does not protect against a compromised OS, swap, or crash dumps.

A **Sync Chain** is the cryptographic identity rooted in this recovery material.
The **Chain ID** is public: a versioned full SHA-256 digest of the root public key.
A Chain ID cannot recover a phrase or enroll a device. Losing every admin/device
and the recovery phrase means losing access. If the phrase is compromised,
create a new chain. See [the identity specification](docs/architecture.md).

## Devices, approvals and status

```sh
wayfinder chain show
wayfinder status
wayfinder tui
wayfinder devices
wayfinder device revoke DEVICE_ID
wayfinder auth list
wayfinder auth revoke GRANT_ID
```

The TUI observes a running agent. Status includes the gateway, connection state,
Chain ID, Device ID, name and role. Stale status is reported offline. Device and
grant administration requires the local agent to be connected. Revocation is
permanent for that Device ID at this gateway; it closes the session, cancels
in-flight work and prevents reconnect. To replace a revoked installation, join
with a fresh device key in a fresh data directory. Grants already approved by a
device are separate: revoke its grants too when responding to compromise.

Names are display labels; `exec` accepts a stable Device ID or an unambiguous name
**within the authorized chain**. Ambiguous names fail. A target is always required.
`nodes` lists that chain's devices, roles, last-observed timestamps, online state
and revocation status. There is no entry node or implicit local target.

## Connect ChatGPT or another MCP client

Configure **https://mcp.usewayfinder.app** as the remote MCP URL and use OAuth.
The gateway supports dynamic client registration with exact registered callback
URIs, S256 PKCE, and `read` / `exec` scopes. The browser displays a pairing code.
On a connected administrative device:

```sh
wayfinder authorize ABCDEF-123456
```

The CLI shows the gateway, chain, requesting client ID/name, redirect and exact
requested scopes. Client names are self-reported. Approve only a connection you
initiated and recognize; type `yes` locally. Refresh the browser page to return to
the MCP client. Requests expire after ten minutes and can only be approved once.
**Never enter your recovery phrase in the browser or ChatGPT.**

`read` allows device discovery. `exec` allows arbitrary shell execution on chain
devices with the agent's OS privileges. A root agent executes commands as root.
There is no command sandbox. Chain isolation does not alter this OS boundary.
Access tokens expire after one hour; rotating refresh tokens last up to 30 days.
`wayfinder auth list` shows grants and scopes; revocation invalidates subsequent
requests and refreshes. Already-dispatched commands are not undone by grant
revocation. See [OAuth and self-hosting](docs/remote-mcp.md).

## Run at boot on Linux

Run this as the OS account whose privileges commands should receive:

```sh
./wayfinder-service.sh install
```

The script builds/installs **only the agent**, installs the native `wayfinder`
command, and enables `wayfinder.service`. If no chain is enrolled, the service
waits for `installation.json`; create/join interactively, then run
`sudo systemctl start wayfinder.service`. It reconnects after boot with bounded
backoff. `WAYFINDER_DATA_DIR` selects a non-default private data directory for the
installer. The CLI accepts `--data-dir PATH` on every command. Default on Linux:
`~/.local/share/wayfinder`. Private directories/files use 0700/0600.

## Self-host the gateway

```sh
cargo build --release -p wayfinder-gateway
./target/release/wayfinder-gateway \
  --data-dir /path/to/private/gateway-state \
  --listen 127.0.0.1:3000 \
  --public-url https://wayfinder.example.com
```

Put a TLS reverse proxy in front; pass WebSocket upgrades, streamed bodies,
Authorization and Origin, rewrite upstream Host to `127.0.0.1`, and disable
caching/logging of credential-bearing requests. Keep the origin on loopback.
See [deployment details](docs/remote-mcp.md) and
[the generic systemd unit](deploy/wayfinder-gateway.service).

Create/join with `--gateway https://wayfinder.example.com`. To move an existing
device, stop its agent, run `wayfinder gateway https://wayfinder.example.com`,
confirm the destination, and restart. This reuses the device and Chain ID.
Revocations and grants are gateway-local: a fresh gateway has neither; moving a
chain does not copy revocation history or trust old OAuth tokens. Move every
wanted device deliberately and reconnect MCP clients to the new URL. No silent
fallback occurs. HTTP is allowed only for explicit loopback development origins.

The gateway handles plaintext commands and results at the application layer.
This is **not end-to-end encryption past the gateway**. Hosted users trust its
operator with MCP traffic and command routing. Self-hosters control this trust
boundary. Neither gateway receives recovery phrases or private identity keys.
Cloudflare provides the official deployment's ingress/TLS/private connectivity;
it implements no Wayfinder identity or protocol semantics.

## Development and validation

```sh
./build-development.sh
cargo build -p wayfinder-gateway
./validate.sh
python3 -m venv /tmp/wayfinder-validation
/tmp/wayfinder-validation/bin/pip install cryptography mnemonic websockets
/tmp/wayfinder-validation/bin/python tests/sync_chain.py
```

The process-level exercise uses disposable material, temporary state, real agent
sessions, OAuth and MCP calls. It prints check names only, never secrets. It
replaces the old peer/application integration exercise. See
[validation and security review](docs/validation.md).
