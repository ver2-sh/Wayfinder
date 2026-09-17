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

**Private and unreleased today:** anonymous consumer downloads and update checks
are not yet available. The following is the intended release installation path
once public releases exist; it requires no Rust, Cargo, compiler or repository
checkout. `usewayfinder.app` is the stable public install front door and redirects
to the corresponding public GitHub Release assets. Do not supply private
credentials to installer commands.

Linux x64/ARM64, WSL (inside Linux), and macOS Intel/Apple Silicon:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://usewayfinder.app/install.sh -o wayfinder-installer.sh
# Inspect the downloaded installer, then:
sh wayfinder-installer.sh
wayfinder
```

Windows x64, from PowerShell:

```powershell
Invoke-WebRequest https://usewayfinder.app/install.ps1 -OutFile wayfinder-installer.ps1
# Inspect the downloaded installer, then use a process-only policy:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\wayfinder-installer.ps1
wayfinder
```

`-ExecutionPolicy Bypass` applies only to that PowerShell process. It does not
change CurrentUser or LocalMachine policy; organizational MachinePolicy/UserPolicy
Group Policy still takes precedence. Wayfinder never calls `Set-ExecutionPolicy`.

Installers place the binary in the current user's Cargo bin directory (normally
`~/.cargo/bin`; Cargo itself is not required), update PATH, and write an install
receipt for updates. Open a new terminal if PATH has not refreshed. Archives and
SHA-256 sums also support manual installation. No MSI is generated. Windows ARM
users may use x64 emulation. Signing/notarization and the upstream PowerShell
checksum limitation are documented in [release readiness](docs/releases.md).
Release CI verifies cargo-dist 0.33.0 archives against repository-pinned SHA-256
hashes before execution, including in the privileged publishing job.
Do not disable OS protections to install an unsigned build.

## Normal usage

Run `wayfinder` in a terminal to open the management TUI (`wayfinder tui` is
also supported). The full-screen sections cover Overview, Devices, MCP Grants,
Browser pairing, Gateway, Agent and Updates. Before enrollment, choose Create Sync
Chain or Join Sync Chain. Use arrows to select a section, Tab or Enter to focus a
list, and PgUp/PgDn to scroll details. Context keys appear in each view; `r`
refreshes, Esc cancels a prompt, and `q` or Ctrl-C quits. Destructive actions and
pairing approvals require typing `yes` after reviewing their details.

For an enrolled installation, opening the TUI automatically starts a temporary
agent if none is running. Closing it stops only that temporary agent; attached
agents and installed services continue running. **Agent → I** enables automatic
startup for the current OS user. Gateway changes restart an owned temporary agent,
including after a failed change; an independently running agent must be stopped
explicitly first.

Recovery input is hidden and has no history. Creation displays the recovery words
and requires explicit confirmation that they have been stored securely. Nothing is
copied automatically. Use a private, unrecorded terminal; terminal cleanup cannot
erase an external recording.

CLI commands remain available for servers and automation. Bare `wayfinder` fails
clearly when input or output is redirected; scripts must supply a subcommand.
For example:

```sh
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

The TUI attaches to a running agent or starts a temporary one automatically. Status includes the gateway, connection state,
Chain ID, Device ID, name and role. Stale status is reported offline. Device and
grant administration requires a reachable gateway. Revocation is
confirmed explicitly (use `--yes` for deliberate CLI automation) and permanent for that Device ID at this gateway; it closes the session, cancels
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

## Background agent and automatic startup

Run as the OS account whose privileges remote commands should receive:

```sh
wayfinder service install    # configure startup and start; enroll first
wayfinder service status
wayfinder service stop
wayfinder service start
wayfinder service restart
wayfinder service uninstall  # stop and remove startup; preserve identity/config
```

Linux uses **user-scoped systemd**, macOS a per-user **LaunchAgent**, and Windows
a **Task Scheduler logon task** with interactive logon and limited run level.
None requests elevation or installs a root/Administrator/SYSTEM service. Do not
run installation under an elevated account unless that is deliberately the
privilege boundary you want. Background installation is separate from downloading
the binary and is never silently enabled by the installer.

Linux user services normally depend on a user session. Headless boot operation
may require an administrator deliberately enabling lingering for a dedicated
unprivileged account (`loginctl enable-linger USER`). Wayfinder does not do this.
WSL uses the same Linux path if systemd and a user manager are enabled; otherwise
use a foreground daemon or a TUI-owned agent. macOS LaunchAgents and Windows
logon tasks start at login, not before login, and need that user's session.
Service command failures are reported; an absent user bus is not success.

`--data-dir PATH` works for CLI and TUI. Each directory gets a distinct startup
name and an exclusive agent lock; no duplicate agent can own that directory.
The default Linux data directory is `~/.local/share/wayfinder`. Unix private
state uses 0700 directories and 0600 files. Startup definitions retain absolute
binary/data paths; reinstall them if you move the binary. Status distinguishes
a startup definition from a running process; connectivity is reported separately.

The previous source-building, `/usr/local/bin`, system-level installer is removed.
If you previously deployed it, deliberately stop/disable its old system unit as
administrator before enabling user startup. Existing identities are retained;
there is no automatic privilege or installation migration.

## Updates

```sh
wayfinder --version
wayfinder update --check
wayfinder update
```

Interactive startup checks the stable channel in the background at most daily,
caching failures too. Explicit checks bypass the cache. No chain/device data,
keys or telemetry are sent. Network failures and inaccessible private releases
are reported without interrupting operation. No update installs automatically.

`update` reports versions and asks for explicit confirmation. A matching dist
receipt permits one-action updating through axoupdater and the release installer;
users do not need to rerun the original installation command. On Windows, the
updater uses process-scoped PowerShell `-ExecutionPolicy Bypass`; normal direct
installs do not need an existing Bypass policy or a permanent policy change.
Group Policy remains authoritative; if it blocks the installer, the update fails
and the previous installation is restored. See [release limitations](docs/releases.md).
Missing/mismatched
receipts refuse replacement: use the owning package manager (for example
`brew upgrade wayfinder` for a future Homebrew installation), or your source/manual
installation process. No package-manager channel is provisioned yet.

Updates stop/restart the managed agent for the selected data directory, including
restarting after an update failure. Independently launched daemons must be stopped
explicitly. Stop other Wayfinder instances using the same binary before updating,
especially on Windows. The TUI stops its temporary agent before updating and
resumes it afterward, including after failure. Reopen the TUI after a successful
update to run the new executable.
Identity, recovery material, grants and gateway configuration are not modified.
See [release maintenance and platform limitations](docs/releases.md).

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

## Development and release maintenance

Source builds and Rust requirements are in [development](docs/development.md).
See [release maintenance](docs/releases.md) for version bumps, local preflight,
intentional tags, artifact checks, hosted-minute controls and signing readiness.
[Validation and security review](docs/validation.md) documents the disposable
integration tests. Gateway self-hosting and provider-neutral operation are unchanged.
