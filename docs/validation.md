# Validation record

## Peer-service privilege boundary revalidation — 2026-09-14

This pass starts from Wayfinder `1cb5cbc5488eb7404f07074bf28813a34eb7985a`
and Norted-Server `499de722494ab361c5211cc8998845b14c562a08`. Changes remain
local and unpushed. Earlier results below describe the previous implementation;
the application credential instructions in the current peer-service/Link docs
supersede that implementation's full-control discovery contract.

Wayfinder now publishes an explicit, separate `PeerServiceDescriptor` for each
`daemon --peer-service SERVICE=/absolute/path` option. The random capability is
independent of administration and MCP credentials. `/peer-service` decodes only
sanitized status, registration/renewal and unregistration. Both this API and the
local stream listener enforce the configured service name. The administrator's
`/control` authority is retained; its descriptor no longer advertises a transport
listener. Norted uses only `link.wayfinder_peer_service`, with no old-path fallback.

### Existing workspace checks

Wayfinder passed `cargo fmt --all -- --check`, `cargo check --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
(no repository test cases), `cargo build --release`, and `git diff --check`.
Norted passed `./validate.sh` (214 tests passed, one existing ignored),
`cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo build -p norted-server`, `cargo build --release -p norted-server`, and
`git diff --check`. No repository tests were added.

### Isolated boundary proof

External driver `security.py` passed 58 assertions against two fresh Wayfinder
instances using the final release binary:

- Observation contains only `nodes` and `conflict`; every node contains exactly
  `id`, `name`, `local`, and `reachable`.
- Service capability differs from both admin and MCP credentials.
- Admin status/details/create/invite/join/remove reject the service bearer with
  HTTP 401. Administrative operations also fail the service API decoder (422).
- MCP rejects the service bearer (401). Private identity/config/state paths and
  `/control` do not exist on the service endpoint (404).
- Register/unregister/open of an unrelated service name fail scope checks.
  The admin bearer also fails authentication at the application stream listener.
- Registration, renewal, unregistration, unavailable-after-unregister and actual
  bidirectional Noise echo streams pass.
- A separate Unix UID (65534), granted only the 0600 capability file, successfully
  observes members while filesystem reads of identity.json, config.json,
  state.json and control.json all fail with PermissionError.

### Norted regression

The prior two-node smoke/failure drivers were adapted outside the repositories
to use the new capability paths. Fresh Wayfinder identities and independent
Norted profiles reference an existing GGUF and llama.cpp binary; no model/runtime
bytes are copied. An old setup-driver assumption about Norted's runtime descriptor
location failed initially; the driver was corrected to use `runtime/servers`.
This was a harness failure, not an application failure.

Both Norted processes then ran in private mount namespaces masking their
Wayfinder private directories with empty directories. `/proc/PID/root` checks
confirmed that neither process could see Wayfinder identity/config/state/control
files. The separate service descriptors remained visible. With that restriction:

- `smoke.py`: 42 assertions passed, both A→B and B→A. Discovery, remote inventories,
  local and qualified remote inference, nonstreaming/streaming Chat Completions,
  Responses and Completions, owner embedding capability rejection, streaming and
  nonstreaming cancellation, owner load/unload, no JIT load and state refresh.
- `failures.py`: 44 assertions passed. Source/target/hop/version/size/operation
  rejection, exact owner routing, deterministic duplicate aliases, no fallback
  after owner profile removal, explicit interrupted-stream error, stale peer
  handling, local inference during Wayfinder loss, reconnect and restored remote
  inference in both directions. Independent profile stores remained intact and
  neither model nor runtime installations appeared in the peer data directories.

- `tui.py` and `tui-actions.py`: real Ratatui captures show both nodes in
  Models/Overview and the selected remote owner in Profiles; 16 action assertions
  passed for owner load/unload, unchanged local backends/profile files, disabled
  remote editing and local-only Runtime views.
- `cleanup.py`: 12 capture/lifecycle assertions passed. Isolated TUIs, Norted
  servers, native backends and Wayfinder daemons were stopped; Norted listeners
  closed and administration/application capability descriptors were removed.
  Production processes were not targeted.

Reproduction commands (drivers are intentionally outside the repositories):
`python3 security.py`, `python3 setup.py` with its runtime descriptor lookup
corrected by `python3 load.py`, `python3 restricted.py`, `python3 load.py`,
`python3 smoke.py`, `python3 failures.py`, `python3 tui.py`,
`python3 tui-actions.py`, and `python3 cleanup.py` from the scratch directory.

Scripts, logs and assertion records are in
`/srv/norted/scratch/norted-link-boundary`, outside both repositories. This is
real multi-process Linux/llama.cpp validation on one host; no second physical
machine or Windows/macOS deployment was tested. Existing q27/NInfer/DFlash2/vision
contracts passed workspace checks; no new hardware inference runs for those
engines are claimed. No federation semantics or runtime/model implementations
were changed. Capability files are ephemeral: regrant application file access
after restart and explicitly remove a stale descriptor after an unclean stop.


Validated on Linux with Rust/Cargo 1.98.0. No new repository test suite was added. Temporary external smoke drivers exercised actual daemon processes and the real control, MCP and encrypted peer transports.

## Static checks and build

Passed:

- `cargo fmt --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --release`
- `git diff --check` (including the staged replacement)

The release binary is `target/release/wayfinder`.

## Isolated release smoke

Three daemons used fresh private temporary directories, distinct randomly allocated `127.0.0.1` MCP/peer ports, and separate OS-assigned loopback control ports. No production service, tunnel or repository `.env` was used.

Passed:

1. Standalone `nodes`, MCP initialization and tool discovery; exactly `nodes` and `exec`.
2. Create network on A; generate invitation; authenticate preview on B; join B through A.
3. Reject reuse of A's consumed invitation; join C through B.
4. All three control backends converge on identical member IDs/names and report reachability. These are the same backends used by the TUI.
5. MCP through A discovers all three nodes and executes locally, on B, and on C. C also routes back to A. Returned identities, stdout, stderr and real nonzero exit statuses are checked.
6. Remote cwd and environment overrides; explicit spawn failure; timeout and signal result; 1 MiB output overflow/truncation.
7. Close the MCP TCP connection during a local command and during a routed command; observe both shell PIDs terminate promptly.
8. Stop C; A reports it offline. Explicit targeting of C fails with no stdout, no exit success and no fallback. A→B remains usable.
9. Restart C; membership and reachability recover.
10. Reject invalid MCP bearer, browser Origin and non-loopback Host. MCP and control credentials are rejected in the other authentication domain.
11. Unknown paths, OAuth discovery paths, `/mcp/extra` and `/mcp?x=1` return 404 without a bearer challenge.
12. Short-lived invitation expires and is rejected.
13. A fresh untrusted Noise identity completes encrypted transport but is rejected for routed execution.
14. Stop B and C; remove C through A. A rejects C's original Noise identity despite C retaining its old state/private key.
15. Restart retained B; it reconciles C's removal made while B was offline.
16. Attach the real Ratatui client through a PTY at 80×24; quit it and confirm A's daemon/control endpoint remains alive.

All temporary daemon processes were terminated and reaped in cleanup, all allocated listener ports were checked closed, and the temporary runtime directories were removed. The live checkout's original service and tunnel were not stopped or restarted. The Rust implementation preserves the routing behavior of the original commit `1f4d37c`.

## TUI-managed lifecycle (2026-09-10)

Passed formatting, workspace check, Clippy with warnings denied, release build, and diff whitespace checks. Temporary smoke drivers outside the repository used isolated private directories and a real 120×24 PTY; no repository test code was added.

- Q, Ctrl-C keypress, and SIGINT exit a TUI-owned daemon with its listeners closed, descriptor removed, and directory lock released.
- The same exits leave an external daemon healthy and its descriptor unchanged. `status` and `control` remain usable.
- Standalone daemons shut down cleanly on SIGINT and SIGTERM.
- Malformed configuration/identity and occupied MCP/peer ports return the original startup error without opening the TUI or leaving listeners/locks behind.
- Stale and malformed control descriptors allow a fresh owned daemon to start. Terminal initialization failure also cleans up the owned daemon.
- A held directory lock with no control endpoint fails within the bounded startup period. Delayed publication of an external daemon's descriptor is retried successfully without taking ownership.

All smoke processes were reaped and temporary runtime directories removed. These lifecycle checks were run on Linux; other platforms remain unvalidated.

## Peer services v1 (2026-09-14)

The peer-service implementation was audited against upstream `848305b`. Linux
workspace formatting, check, Clippy with warnings denied, release build,
`cargo test --workspace`, and diff whitespace checks passed. The workspace has
no test cases; direct integration supplied the service validation. No repository
tests were added.

Two isolated release daemons used distinct identities, private directories and
loopback peer endpoints on one host. Both directions passed registration/renewal,
credential isolation, takeover rejection, non-loopback endpoint rejection,
missing-service errors, a 32 MiB echo with byte-for-byte integrity, slow-reader
backpressure, disconnect propagation and unregister. The MCP bearer was rejected
by the service-open listener. A third Wayfinder member joined normally with no
application service and did not appear as an active application peer.

An application integration then ran two Norted servers and real local llama.cpp
backends through these Noise connections. Bidirectional streamed/non-streamed
requests, original-client cancellation, remote control, daemon disconnect and
reconnect passed. The application protocol rejected invalid source/target/hop
identities, incompatible versions and oversized frames. Its public API and private
control credentials remained separate. Wayfinder carried application bytes without
adding application concepts or using MCP/shell execution for the data plane.

There is no second physical machine connected yet. These checks exercise real
processes and authenticated peer connections on one Linux host; physical LAN,
firewall and cross-platform behavior are not claimed by this validation. Existing
production services were left running throughout.

## Limits of this validation

This is isolated end-to-end smoke validation, not a claim of exhaustive protocol, cryptographic or distributed-systems verification. Windows/macOS execution and terminal behavior, real LAN firewall configurations, external reverse proxies/tunnels, simultaneous membership forks and disk/power-loss fault injection were not validated. The exact membership/revocation limitations and manual fork recovery are documented in [architecture.md](architecture.md).
