# Validation

Run the existing checks with current source:

```sh
./validate.sh
cargo build --workspace
python3 tests/sync_chain.py
python3 tests/tui_service.py
```

The Python suites need `cryptography`, `mnemonic`, `websockets`, and `pyte` in a
private development virtual environment. They create disposable chains and
services and suppress recovery phrases, device keys and bearer credentials.

For hosted integration, use the same agent binaries and suite with separate
public origins:

```sh
WAYFINDER_TEST_GATEWAY=https://gateway.usewayfinder.app \
WAYFINDER_TEST_MCP=https://mcp.usewayfinder.app \
python3 tests/sync_chain.py
```

The suite exercises real enrollment, two devices in one chain, an isolated second
chain, independently derived HKDF/Chain IDs, invalid certificates/signatures,
explicit CLI OAuth approval, chain-bound grants, maximum-size output, deadlines,
process-group cancellation on HTTP disconnect, disconnect without command replay,
scopes, device/grant revocation, refresh rotation and replay detection. It also
enrolls a fresh device with the same phrase at an independent Rust gateway and
checks that old device certificates cannot self-admit there.

Self-hosted runs additionally restart the Rust gateway and inspect only the
private disposable SQLite file for accidental persistence of recovery material,
private keys or raw bearer tokens. Hosted restart/deployment and hibernation
checks belong to the infrastructure validation record in Wayfinder-Cloudflare.
No migration workflow, state-transfer format or old-layout migration is present.

The TUI suite validates hidden phrase input, modal confirmation, mouse/keyboard
interaction, nonblocking lookups, terminal restoration, managed/temporary agent
ownership, update failure recovery and service cleanup. Gateway display is
informational; the URL is selected at enrollment.

Do not treat local Worker emulation as proof of public transport behavior. Verify
HTTP cancellation and proxy propagation against the public MCP origin, and
verify the hosted service with the former private gateway/tunnel stopped. Keep
live disposable credentials private and revoke their devices after validation.
