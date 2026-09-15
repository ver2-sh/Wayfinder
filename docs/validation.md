# Remote MCP and local OAuth validation — 2026-09-15

Inspected the clean checkout at `0474285`, fetched origin and confirmed the local
branch matched `origin/master` before editing. No changes were pushed. Inspected
the installed systemd unit and only non-secret host configuration fields; the
running production daemon, credentials, reverse proxy and tunnel were not changed.

## Repository checks

- Debug binary built with `cargo build -p wayfinder`.
- `./validate.sh`: formatting, workspace check, Clippy all targets with warnings
  denied, and workspace test/doc-test harnesses. The Rust harnesses contain zero
  tests; the behavioral evidence below is separate.
- Existing `python3 tests/dynamic_apps.py`: 51 passing checks across three
  isolated daemons, including authenticated peers, application UID isolation,
  private files, registration lifecycle and cross-protocol credential rejection.
  Only its MCP path and explicit listener opt-in setup changed.
- `git diff --check` and CLI auth help inspected.

## MCP and credential behavior

A temporary external validation client built against official `rmcp = 3.3.0`
used `StreamableHttpClientTransport` and `ClientServiceExt`, rather than a custom
MCP client. Two fresh daemons joined using real invitations and Noise peers.
Both legacy initialization and the current `server/discover` lifecycle were
exercised. SDK discovery, tool listing, node listing and execution on the second
peer passed with a read+exec credential. A read-only credential could list nodes
but could not execute. OAuth-issued access tokens used the same SDK path.

Additional local HTTP checks covered missing, malformed, wrong-secret, unknown-ID
and revoked credentials; Origin/Host rejection; removed `/mcp` and query-token
routes; GET 405 behavior; MCP/control credential separation; stored hash-only
credentials; list output excluding verifiers; last-used timestamps; immediate
revocation and persistence across restart; mode 0600; disabling the MCP listener
while retaining private control.

## OAuth behavior

Exercised metadata discovery, local confidential client registration, browser
pending request, explicit private approval, state/issuer in the redirect, and
S256 code exchange. Both client-secret Basic and form-post authentication passed.
Negative checks covered malformed form requests, wrong client secret, wrong
redirect, unsupported admin scope, wrong PKCE verifier, consumed authorization
code, wrong resource audience, revoked grant and revoked OAuth client.

Refresh rotation invalidated the previous access token. Reusing a consumed
refresh token revoked the grant and rejected its current access/refresh tokens.
OAuth client/grant state persisted across daemon restart. Secrets and raw tokens
were absent from persistent credential JSON. All issued tokens stayed in the
temporary harness's memory and were not printed.

The temporary harness and SDK client are under `/tmp/wayfinder-mcp-validation`
in this development environment. No new permanent test framework or protocol
stack was introduced into the repository.

## Evidence limits

Validation used loopback HTTP behind the intended TLS boundary, isolated local
peer processes, and current upstream SDK/specification sources. It did not expose
the live host, provision DNS/certificates, run Caddy, connect a production ChatGPT
account, or execute on a second physical machine. Follow the
[host cutover runbook](remote-mcp.md#existing-norted-host-cutover) and verify the
actual ChatGPT OAuth UI after HTTPS is live. Windows remote MCP/OAuth was not
runtime-tested. Unix is the validated platform for this change.

---

# Dynamic application interface validation — 2026-09-14

Inspected the clean checkout at `9d31fba`, fetched origin, and confirmed it matched
upstream before editing. No changes were pushed.

## Workspace and generic integration

`./validate.sh` passed formatting, workspace check, Clippy across all targets with
warnings denied, and workspace tests. Debug and release executables built.
`git diff --check` passed. Linux is the validated dynamic-application platform.

`python3 tests/dynamic_apps.py` passed 29 assertions using real processes and three
fresh identities. Its independent example application uses `echo.private.v1`.
Tests cover:

- Normal invitation linking without application-specific configuration.
- Exact-node, bidirectional encrypted echo, including 200 KB payloads in bounded
  chunks, and ordinary service absence on the third member.
- Sanitized node discovery, invalid names/addresses/credentials, unknown exact
  targets and rejection of administration/execution operations by the app decoder.
- Socket permissions, independent peer-UID rejection (when tested as root),
  session ownership against takeover/unregister, and rejection of a live
  registration credential by MCP and private administration.
- Immediate registration removal on application kill, application restart without
  daemon restart, and daemon crash/restart followed by automatic application
  reconnection and successful service use.
- Unrelated service registration and explicit unregistration.

Additional terminal validation exercised a TUI-owned daemon's automatic socket,
read-only live service view, an attached TUI's exit without daemon shutdown, and
owned-TUI shutdown removing the socket. All four assertions passed. Both startup
paths share the same application endpoint implementation.

The peer encryption/membership transport is retained. Only its local byte-stream
input was generalized to accept Unix sockets as well as TCP. Registration state
is in memory, owned by live sessions; there is no application configuration file,
lease, capability descriptor, replicated service catalogue or application metadata.

## Evidence and limits

Local captures and check logs are retained outside this repository. The checked-in
example and generic integration driver reproduce the generic protocol tests.
There was no linked second physical machine available. LAN/firewall behavior and
Windows/macOS dynamic application transport are not validated; the latter is
unsupported in this iteration. Processes sharing an OS account share that trust
boundary; the application API does not provide filesystem or shell authority.
