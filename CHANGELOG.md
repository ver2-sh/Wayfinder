# Changelog

## v0.2.1 — 2026-10-18

- Allow existing Admin devices to promote Members and demote delegated Admins through signed CLI and TUI operations without re-enrollment or replacing device identities.
- Persist gateway-local delegated roles across restarts, enforce effective permissions on each administrative request, and preserve immutable root-authorized Admin certificates.
- Add confirmations, effective-role status, and cross-runtime security tests for both self-hosted and Cloudflare gateways.

## v0.2.0 — 2026-10-18

- Add Wayfinder-managed, host-local code intelligence backed by upstream Serena with private Python, Node.js and language-server setup.
- Expose first-class code MCP operations for semantic navigation, references, diagnostics, symbol editing, cross-file renaming and project memories, authorized by the existing exec grant.
- Preserve legacy agent discovery and shell behavior while adding authenticated code-capability negotiation to updated agents.
- Add independent code-runtime updates with pinned artifact hashes, disposable MCP qualification, safe idle activation and rollback without replaying user edits.
- Add local code management and Settings controls. No separate backend UI, account, public port, or telemetry.

---
