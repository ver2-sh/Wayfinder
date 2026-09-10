# Validation record

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

All temporary daemon processes were terminated and reaped in cleanup, all allocated listener ports were checked closed, and the temporary runtime directories were removed. The live checkout's original service and tunnel were not stopped or restarted. The original commit `1f4d37c` remains the branch HEAD; the Rust implementation preserves its routing behavior.

## Limits of this validation

This is isolated end-to-end smoke validation, not a claim of exhaustive protocol, cryptographic or distributed-systems verification. Windows/macOS execution and terminal behavior, real LAN firewall configurations, external reverse proxies/tunnels, simultaneous membership forks and disk/power-loss fault injection were not validated. The exact membership/revocation limitations and manual fork recovery are documented in [architecture.md](architecture.md).
