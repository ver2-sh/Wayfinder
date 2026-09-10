# Architecture

## Composition

The Tokio composition root is `crates/wayfinder`. It loads private state under a directory lock, binds all three listeners before publishing control discovery, and cancels services together on SIGINT/SIGTERM or listener failure. The foreground daemon is suitable for an OS supervisor. The Ratatui process is disposable and independent.

| Crate | Responsibility |
| --- | --- |
| `wayfinder-core` | Versioned contracts, identity, configuration, signed membership validation, private atomic storage |
| `wayfinder-exec` | Fresh local shell, input validation, bounded pipes, exit status, cancellation and process cleanup |
| `wayfinder-network` | Noise transport, invitations, replicated membership, reachability, exact-target direct execution |
| `wayfinder-api` | Private loopback administration and descriptor-based client |
| `wayfinder-mcp` | Official rmcp Streamable HTTP adapter; exactly `nodes` and `exec` |
| `wayfinder-tui` | Terminal frontend using only the private API client |
| `wayfinder` | CLI, initialization, daemon startup/shutdown, TUI attachment |

There is no web dashboard, shell session store, filesystem API, central inventory, telemetry, coordinator, or cloud dependency. Every retained member has the same administrative authority. Any member can introduce another node and be an MCP gateway. Hosts remain responsible for shell capabilities and OS access control.

## Request paths

**MCP:** exact `/mcp` path → constant-time hashed bearer comparison → reject Origin → validate Host → rmcp → choose exact ID/name → local execution or direct peer request. Unknown paths return 404 before bearer authentication, preserving commit `1f4d37c`. IDs take precedence over display names. The official SDK also enforces its conservative Host policy. A reverse proxy rewrites Host to loopback and supplies encrypted client transport.

**Control:** private `control.json` → loopback HTTP → distinct bearer → Origin and loopback Host validation → narrowly scoped network administration. The client disables HTTP proxies and redirects. There is no control operation for executing host commands. This separation prevents accidental credential reuse; it is not isolation from the same OS account.

**Peer execution:** pinned Noise connection → current membership authorization → exact current membership-head match → exact local target ID → local executor → encrypted result. The target never forwards again. The receiver checks authorization anew for every execution connection. A membership mismatch requires synchronization before another request. Commands are never retried automatically. Unknown and unreachable targets never fall back to the entry node.

Connection establishment failure means nothing was dispatched. Connection loss after sending is an explicitly unknown outcome. TCP disconnect during execution cancels it on the receiver, but cancellation cannot undo side effects that already happened. Revocation does not retroactively cancel admitted executions.

## Identity and transport

Each node generates an Ed25519 signing identity and a separate X25519 Noise static key locally using established libraries. The stable node ID is its Ed25519 verifying key in hex. Private keys are stored only in `identity.json`, never replicated, returned by MCP, logged, or injected into subprocess environments. Peer descriptors contain only public keys, display names and IP endpoints.

The transport uses [snow](https://docs.rs/snow/0.10.0/snow/), implementing `Noise_XX_25519_ChaChaPoly_BLAKE2s`, with a Wayfinder protocol prologue. The initiating side pins the responder's static key before completing the handshake or sending application data. The responder obtains the authenticated initiator static key from the handshake. Both then use Noise authenticated encryption; there is no custom cipher, key agreement, or signature algorithm.

One request/response uses one TCP connection. Length-prefixed Noise records are limited to 65535 bytes; larger JSON messages are chunked into authenticated records with a bounded total length of 16 MiB. Handshake and first-message reads have a five-second deadline. Sync connections are short-lived and bounded. Peer connections are not persistent shell sessions. This version supports direct reachable IP endpoints, not NAT traversal or multihop routing.

## Linking

The introducing daemon stores an in-memory hash of a random 256-bit invitation secret, expiry and network binding. A copy-safe base64url invitation carries the secret, network ID/name and full introducing public descriptor. The operator's private transfer of that invitation establishes the initial trust pin; Wayfinder does not trust a DNS response or arbitrary self-signed certificate.

Preview connects with that pin and validates the outstanding invitation before displaying the network. Admission checks that the new descriptor's Noise key matches the authenticated connection, validates names/keys, synchronizes first, signs a one-node addition, atomically persists it, and consumes the invitation. The joining node verifies the signed history and invitation binding, persists its membership, then exchanges membership with other peers.

Invitations live for 1–600 seconds (TUI: 600), are single-use, and do not survive inviter restart. At most 64 may be outstanding. Expiry depends on local wall clocks. Network admission is not a distributed transaction: if the inviter commits but the response is lost or the joining disk write fails, the node may appear in membership without having completed its local join. Remove that incomplete admission through the introducer and issue a new invitation; do not assume a failed join response rolled back the introducing node.

## Membership consistency and revocation

Membership is a signed, append-only revision chain, rooted in the network's random 256-bit ID and signed one-node genesis. Each revision binds the exact parent hash, network ID/name, author and sorted full public member set. A revision must add or remove exactly one descriptor and be signed by a member of its parent. Retained descriptors cannot be rewritten. Names, IDs and Noise keys are unique. Validation rejects invalid signatures, unknown versions, malformed chains and duplicate identities. Limits are 128 members, 4096 revisions and 8 MiB of serialized history.

Sequential edits are serialized within the introducing/removing daemon and synchronize with reachable members before committing. Every three seconds each node exchanges its history directly with advertised peers, in parallel, with a three-second peer deadline. A valid extending chain replaces local state atomically. A shorter prefix never rolls state back. Membership converges across connected peers after sequential edits; reachability remains each observer's local view, and is not replicated as authority.

An offline **retained** node accepts a signed extension rooted in its existing history. A previously unknown peer can introduce itself by a valid extending chain proving its membership, so returning nodes can catch up even when other members joined during their absence. A removed peer cannot use stale membership to bypass a node's newer local chain. Synchronization traffic has no execution authority; execution separately requires current membership on the receiving node.

**Revocation is eventual, not instantaneous or globally linearizable.** Once a receiver has persisted a removal, it rejects that peer for new execution connections. A disconnected receiver that has not learned the removal can still accept that peer using its old membership. Such nodes must synchronize before you can rely on the revocation there. A removed node may continue displaying stale membership, but possession of that stale state does not authorize it on updated receivers. Its separate local MCP bearer is not revoked by removal; it can still execute on its own host. Protect or stop that endpoint separately if needed.

**Concurrent edits on different members or disconnected partitions can fork the signed chain.** There is no quorum, leader election, Raft, or automatic fork selection. An observed divergent signed history durably sets `conflict`; the affected node blocks administration and peer execution, while standalone local MCP execution remains available. Ordinary sync continues to exchange histories but cannot clear that flag or choose a winning branch. An edit may have returned success before a competing edit is discovered. Do not perform concurrent membership edits; wait for all reachable views to show the new revision before the next operation.

A true fork requires explicit operator recovery, not a blind retry: stop the affected daemons, select one trusted signed history as the shared baseline, restore **only** that public membership into each affected node's version-1 `state.json` with `conflict: false` using private atomic replacement, restart, synchronize, and then retry discarded edits. Keep each node's identity/config unchanged. Review discarded removals before resuming peer execution: choosing a branch without a removal would otherwise reauthorize that node. All retained members must converge on the selected history; an offline member returning with the discarded fork will surface the conflict again. There is deliberately no automatic conflict-reset button that could silently discard a revocation. For uncertain trust, initialize a fresh network and new identities instead. This is a rare administrative recovery limitation of this first implementation, not a consensus guarantee.

## Storage and host boundary

Configuration, identity and membership are separate versioned JSON files in OS application data. The control descriptor has its own distinct random credential generated per daemon start. Writes use a new private file, file fsync, atomic rename and parent-directory fsync on Unix. The directory lock prevents duplicate daemons from using the same state. Unknown formats and missing initialized identity/state fail closed. There are no prototype-format migrations.

Unix file modes are enforced (0700 directory, 0600 private files). Windows ACL configuration remains the operator's responsibility; atomic rename portability and Windows descendant cleanup have not been validated in this pass. Backups must preserve private ownership and permissions. Rollback of a local membership backup also rolls back local revocation knowledge until it synchronizes again.

The daemon's OS account is the capability boundary. All members can request arbitrary execution on each other, and all local administrators can change membership. A compromised authorized member or MCP client can read identity files through its shell access. This is not a hostile-multitenant network or a policy engine. The distinction among MCP, control and peer credentials prevents cross-protocol authentication, not consequences of already-authorized arbitrary command execution.

Execution uses bounded separate stdout/stderr, stdin closed, fresh shell/cwd/env, timeout and cancellation. A process-group guard runs on cancellation or dropped execution futures; kill-on-drop also protects the shell. Ordinary descendants are cleaned up on Unix, including inherited output pipes; detached processes can escape. No commands, outputs, invitation secrets, bearer tokens or private keys are logged by the daemon. Logs are limited to local startup and operational failures.
