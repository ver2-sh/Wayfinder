# Implementation, security review and deployment record

Date: 2026-09-16. The sections below record the original implementation; the
material abuse-resistance follow-up at the end records the subsequent audit.
No real Sync Chain recovery phrase was generated during either validation.
All automated enrollment used disposable material kept out of transcripts/logs.

## Repository changes

`project-wayfinder`:

- Added `wayfinder-agent` and `wayfinder-gateway` crates and gateway service unit.
- Replaced core peer identity/state with `identity.rs`, `protocol.rs`, chain-bound
  OAuth and SQLite `credentials.rs`; retained restrictive atomic local storage.
- Adapted MCP to authenticated chain-scoped routing, required explicit exec target,
  added dynamic OAuth registration and local signed out-of-band approval.
- Replaced CLI/TUI/service UX with chain/device/gateway/grant concepts.
- Preserved the shell executor's stdout/stderr, status, timeout and cancellation.
- Removed `wayfinder-network`, `wayfinder-api`, and old `wayfinder-tui` crates,
  Noise peer transport, graph revisions, invite/link/advertise configuration,
  inbound agent MCP/control/peer listeners, old static bearer administration,
  entry-node semantics and peer-application transport/example documentation.
- Replaced/renamed the existing `tests/dynamic_apps.py` integration exercise with
  `tests/sync_chain.py`. Added an expiry boundary test inside existing OAuth source,
  because waiting/changing the system clock is inappropriate for this security check.
- Updated README and architecture, OAuth/self-hosting and validation documentation.
  Cargo manifests/lockfile now reflect the new dependencies and removed crates.

`Wayfinder-Cloudflare`: corrected current deployment documentation and binding
comment; added the exact, **not yet applied** hostname-only Browser Integrity Check
configuration rule. The existing streaming Worker code, private VPC binding,
tunnel and Custom Domain were retained; live WebSocket testing proved them useful.
No Worker code deployment was required.

`Norted-Utils`: unchanged. No OpenAI Tunnel dependency was reintroduced.

## Final architecture and identity

Agents connect outward to the shared gateway; MCP/OAuth clients use the same
public URL. SQLite stores public roots/certificates, device revocations, last-seen
metadata and chain-bound grants. Connections, nonces and pending OAuth are
in-memory. All device routing uses composite `(Chain ID, Device ID)` keys.
OAuth bearer lookup resolves a hash to a chain/grant pair and joins both keys.

Exact cryptography and signed-byte encodings are in [architecture.md](architecture.md):
256 OS-random bits → 24-word English BIP39 → HKDF-SHA256, salt
`wayfinder/sync-chain/v1`, info `root-signing/ed25519`, 32-byte Ed25519 signing seed.
Chain ID is `wfc1_` plus the full lowercase hex SHA-256 of
`wayfinder/chain-id/v1\0 || root_public_key`. Device IDs use the analogous
`wayfinder/device-id/v1\0` domain and `wfd1_` prefix. Gateway URLs are absent from
identity derivation. They are included in authentication/administration proofs.

Each independent device key receives a root-signed versioned membership certificate
binding chain, root, device ID/key, role and name. Creation produces an admin;
join defaults to member. No root secret persists. Revocation is a permanent
per-gateway device tombstone and closes the session. Existing grants remain
separately revocable. Possession of the root phrase can enroll new administrators.

WSS challenge-response proves device possession with a one-use 256-bit nonce,
5-second authentication deadline, exact gateway audience and certificate digest.
Heartbeat is 15 seconds, liveness deadline 45 seconds, reconnect 1–30 seconds plus
jitter. Dispatch never retries after uncertain delivery. HTTP disconnect and
session loss propagate cancellation to process groups where transport permits.

OAuth uses exact registered redirects, S256 PKCE, state/issuer, resource and scope
binding. An admin confirms the client and scopes locally and signs their digest
with a one-use, 30-second administrative nonce. The 48-bit pairing code expires
in ten minutes. One-use authorization codes expire in one minute. Access tokens
expire in an hour, rotating refresh credentials within 30 days; stored verifiers
are SHA-256, and refresh replay revokes the grant. Grant listing includes scopes,
active status and access/refresh expiration. No account or browser phrase input.

## Validation results

- `./validate.sh`: formatting, workspace check, strict Clippy (`--all-targets`,
  `-D warnings`), workspace tests/doc tests passed.
- `cargo build --release --workspace`: both release binaries built.
- Release process-level validation: **49 checks passed locally**; **46 passed
  against https://mcp.usewayfinder.app**. The hosted run omits stopping/reading
  the gateway process/database because those are deployment-owned. The origin Host
  rejection test is local; Cloudflare path/Host handling is covered by proxy tests.
- The existing Cloudflare `npm run check` passed TypeScript, Wrangler dry-run and
  all three proxy contract tests.
- Agent installer passed shell syntax check and ran successfully on norted.
  Gateway systemd unit passed verification after binary installation (host emits
  unrelated existing xfs system unit deprecation warnings).
- Additional hosted checks exercised exact gateway audience, tampered signed
  operation rejection, absence of inbound agent listeners, grant activity/scope/
  expiry metadata, administrative nonce expiry and idle heartbeat updates.

The integration exercise verifies:

1. Interactive chain creation and explicit CLI OAuth approval without printing
   captured disposable phrases; join via protected stdin.
2. Independent reconstruction of HKDF/root key and full Chain ID in Python;
   deterministic phrase identity, different chain material, independent device keys.
3. Invalid root certificate, mismatched Chain ID, device signature and replay rejection.
4. Both same-chain devices visible; other-chain ID/name exec and revocation denied.
5. Member administration denied; grant chain/scopes exact; read-only exec denied.
6. Unknown redirects/unapproved codes denied, one-use approvals/codes, state/issuer
   preservation, refresh rotation/replay handling and immediate grant revocation.
7. Real stdout, stderr, nonzero exit, signal, timeout, process-group cancellation,
   and two full 1 MiB control-byte streams (worst-case JSON escaping).
8. Agent offline/restart behavior; gateway restart reconnect and durable revocation;
   no retry after dispatch uncertainty.
9. A second independent generic gateway with the same Chain ID and no Cloudflare code.
10. TLS-verified hosted HTTPS/WSS, correct unauthenticated challenge and metadata,
    private loopback origin, and scans confirming no phrase/root/device private key
    or raw bearer/refresh secret in the local gateway database.

The expiry unit test exercises the exact `expires == now` boundary for both pending
approval and authorization code, including code consumption. This is not a full
third-party cryptographic audit or distributed load test.

## Security review findings

| Concern | Result / boundary |
| --- | --- |
| Recovery/key leakage | No protocol field carries private identity material; no phrase argv/env/log output. Creation requires a terminal. Transient secret buffers zeroized where practical. |
| Identity forgery | Strict Ed25519 verification and root/device-to-ID checks precede registration. Stored membership cannot be rewritten. |
| Replay | Session-local challenge once; stateless admin challenge; replay consumption after verified live-device authentication; code/approval one-use and bounded TTL. |
| Cross-chain IDOR | Device/grant queries and socket maps use verified chain keys. No target input selects chain. Negative live tests passed. |
| Revoked reconnect | Durable tombstones reject registration; active socket terminated; gateway restart preserves revocation. |
| Approval confused deputy | Admin-only, connected device required; exact request digest, client, redirect, scopes, gateway and expiry bound; no browser-only consent. |
| PKCE/redirect/state | Existing exact redirect, S256, verifier validation, state/issuer return and one-use code protections retained. |
| Origin exposure | Only 127.0.0.1:3000 listens; old peer port 3001 removed. Worker cannot derive origin from user path/host. |
| Uncertain exec | Error explicitly states unknown outcome; no retry; cancellation tested locally and through Cloudflare. |
| Hosted confidentiality | No E2E claim: gateway and TLS terminator see payloads, gateway is trusted to route commands. |
| Local OS privilege | norted agent is configured as root; commands will run as root. Gateway uses an unprivileged dynamic service user. |

Intentional limits: no root rotation or QR format; no revocation synchronization
across gateways; no high availability/distributed database; bounded authenticated replay/client/session state plus hosted native source limits;
no comprehensive distributed denial-of-service guarantee; no OS protection against a
compromised device, swap or core dumps; Windows/macOS service packaging untested.
A malicious gateway can send commands through an active authenticated channel;
self-hosting changes who is trusted, not that application-layer boundary.

## Live deployment and remaining operator steps

- `wayfinder-gateway.service`: enabled and active on norted, unprivileged dynamic
  user, private SQLite state in `/var/lib/wayfinder-gateway`, origin 127.0.0.1:3000.
- `cloudflared-wayfinder.service`: active and unchanged; existing VPC/Worker/
  Custom Domain reaches the shared gateway over the private tunnel.
- `wayfinder.service`: new agent unit installed and enabled, intentionally inactive
  because `installation.json` does not exist. Obsolete unreleased local state was
  removed after successful hosted validation. No real chain was initialized.
- Disposable hosted test records were audited as revoked and cleared after checks;
  the live registry is fresh for real enrollment.
- Native `/usr/local/bin/wayfinder` and `/usr/local/bin/wayfinder-gateway` installed.
- Old peer/control/MCP agent listeners are gone. No new public port was exposed.

Run this **locally on norted, as root, in a private unrecorded terminal**:

```sh
wayfinder --data-dir /root/.local/share/wayfinder chain create --name norted
systemctl start wayfinder.service
wayfinder status
wayfinder devices
```

Save the phrase securely when displayed. To use a different OS privilege boundary,
install/enroll the agent under the intended non-root account instead. Additional
devices use `wayfinder chain join --name NAME` and a hidden phrase prompt.

Reconnect/reauthorize ChatGPT using `https://mcp.usewayfinder.app`; run the displayed
`wayfinder authorize CODE` on the connected admin device, verify details, type
`yes`, then refresh the browser. Old OAuth clients/grants are intentionally invalid.

One Cloudflare operator step remains: default `Python-urllib` requests receive
edge error **1010**, while Wayfinder and the validation product User-Agent work.
The current Wrangler credential returns **403** for zone security settings and
rulesets, preventing an automatic adjustment. Add the hostname-only configuration
rule in Wayfinder-Cloudflare's `deploy/browser-integrity-rule.json` to disable
Browser Integrity Check for `mcp.usewayfinder.app`, leaving other hosts unchanged.
Then verify default urllib metadata requests. See that repository's README for
the exact policy and Cloudflare documentation. This is an external permission
limitation, not an application auth workaround.


## Material abuse-resistance follow-up (2026-09-16)

The follow-up keeps the existing database schema and permanent device trust state.
Public challenge issuance is stateless; signed-operation replay records survive
reconnects and expire with the challenge. Handshakes and authenticated sessions
have separate capacity, with chain limits. Public DCR is temporary until a grant
is approved. OAuth pending/approved budgets are separate and expired OAuth state
is collected. Durable device creation has a rate budget, not destructive GC.

The existing 49-check process suite remains unchanged. Additional tests in existing
Rust source files cover challenge floods, forged proofs, reconnect/restart replay,
expiry, DCR saturation without durable writes, client persistence, refresh replay
through maintenance, and preservation of revoked devices during expiry/admission.
OAuth tests also saturate the unapproved pool and exercise reserved approved capacity.

There is no reset, migration or device re-enrollment requirement. Deploy gateway
and CLI together because administrative challenges are now opaque MAC-bearing
values. In-progress authorizations and registrations without grants restart;
existing grants and device identity survive. Do not clear live disposable device
tombstones after validation.


Follow-up validation passed `cargo fmt --check`, `cargo check --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`
(five unit tests plus doc tests). Both current debug binaries were explicitly
built before the unchanged `tests/sync_chain.py`: **49 local checks passed** and
**46 hosted checks passed**. A separate disposable local saturation exercise held
128 unauthenticated sockets, verified a live admin's operations still worked,
and verified admission recovered after the five-second handshake expiry.

The release gateway/CLI and Cloudflare Worker were deployed. Before/after hashes
confirmed the original live device trust rows were unchanged, and the original
grant survived. The actual connected Wayfinder client listed `norted` and executed
a harmless command after deployment. Hosted checks used real Rust agents and WSS,
including cancellation, isolation, scopes, revocation and refresh replay. No live
database was reset; disposable test devices were revoked, leaving their tombstones.
Cloudflare `npm run check` passed all four proxy tests, TypeScript and dry-run build.
Live settings confirm three native rate-limit bindings, no observability, no
Logpush and no tail consumers. Browser Integrity remains a material external
permission blocker: stock urllib still receives 403/1010 and Configuration Rules
access receives 403. The hostname-only rule remains correct and unapplied.

A live persistent-connection test using invalid registration bodies returned ten
422 responses followed by 429 with `Retry-After: 60`, without creating clients.
During that source throttle, MCP `/` still returned the expected 401 and both
metadata endpoints returned 200 with the correct issuer/resource. Native counters
are approximate across edge isolates; the test does not claim a strict global cap.
