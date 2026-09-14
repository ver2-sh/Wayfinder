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
