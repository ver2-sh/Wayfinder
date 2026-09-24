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

Self-hosted runs additionally exercise the local application transport against
the real daemon binaries: each daemon receives an isolated
`XDG_RUNTIME_DIR`, the `wayfinder/app.sock` endpoint appears automatically, and
unconfigured same-user clients verify sanitized status (no credentials or
private state), session-owned loopback service registration, registration
stealing and invalid name/address rejection, exact-device `open_service`, an
end-to-end echo round trip through the gateway relay, half-close EOF
propagation, the credential/source/target/service preface, unknown-service,
same-device and cross-chain refusal, and registration teardown when the
application session dies. The suite then restarts the Rust gateway and
inspects only the private disposable SQLite file for accidental persistence of
recovery material, private keys or raw bearer tokens. Hosted restart/deployment and hibernation
checks belong to the infrastructure validation record in Wayfinder-Cloudflare.
The process suite migrates the same installation between independent gateways,
checking unchanged certificate/key/Chain ID/Device ID, destination connectivity,
wrong-root and target-failure rollback (including admission succeeding before
registration fails), agent lock exclusion, and permanent
target tombstones. No state-transfer format or old-layout migration is present.

The TUI suite validates hidden phrase input, modal confirmation, mouse/keyboard
interaction, nonblocking lookups, terminal restoration, managed/temporary agent
ownership, update failure recovery and service cleanup. Gateway migration
requires explicit confirmation and hidden recovery input; cancellation and failed
migration preserve the installation and restore a TUI-owned temporary agent.
Successful TUI migration in both directions preserves the device identity and
reconnects its temporary agent.

Do not treat local Worker emulation as proof of public transport behavior. Verify
HTTP cancellation and proxy propagation against the public MCP origin, and
verify the hosted service with the former private gateway/tunnel stopped. Keep
live disposable credentials private and revoke their devices after validation.
