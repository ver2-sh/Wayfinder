# Development

Contributors need Rust 1.88+ (or newer if a locked dependency requires it), Cargo
and native build tooling. Users installing releases do not. The bundled SQLite
and TLS implementation require a C toolchain; the updater's TLS dependencies also
use CMake. Linux musl builds require musl-tools. Gateway development remains
separate from installing an agent.

```sh
./build-development.sh
cargo build -p wayfinder-gateway
./validate.sh
cargo build --release -p wayfinder
./run-tui-development.sh
```

See [release maintenance](releases.md) for distribution preflight and
[validation](validation.md) for the disposable process-level security exercise.
Development scripts build local binaries only. The obsolete system-level
`wayfinder-service.sh` installer has been removed. For local lifecycle testing,
use a stable binary path with `wayfinder service install` as your ordinary OS
user. Interactive startup control lives in the TUI under
Settings → Start automatically on login; it is registration-only and never
stops a running agent, while `service install` retains its process-affecting
behavior for scripts and automation. Reinstall the startup definition if you
move the binary. Do not overwrite an executable while a service owns it; use
its lifecycle commands.

## Code-intelligence validation

Ordinary `cargo test --workspace` uses only cheap local/synthetic tests and does not acquire language runtimes or start code analysis. The explicitly ignored integration test exercises unchanged upstream tools in disposable projects:

```sh
cargo test -p wayfinder-code --test real_backend -- --ignored --nocapture
```

This opt-in test disables channel updates in its disposable state and downloads the repository-pinned runtime and checks Python/TypeScript symbols, references, cross-file rename, body replacement, project isolation, reuse, and private configuration. `WF_CODE_TEST_ROOT` may point to a disposable test directory to reuse verified downloads; the test refuses existing directories without its own marker. Remove that test directory after use. It does not modify real repositories, the installed Wayfinder agent, global Python/Node installations, grants or services.

The hosted adapter's local `npm run check` includes matching wire and SQLite Durable Object tests; deployment is a separate explicit action.

## Independent code-runtime releases

The release-channel manifest is maintained in Wayfinder-Cloudflare, separately from Wayfinder application releases. The public endpoint is `https://usewayfinder.app/code-runtime/v1/stable.json`. It serves metadata only; verified artifacts come directly from upstream. See that repository's `docs/distribution.md` for the approval/publication procedure.

Local updater tests cover channel validation, immutable release sequences, failed/cached checks, live-session deferral, candidate activation, interruption and rollback. They do not download dependencies. Run the opt-in real MCP qualification separately:

```sh
cargo test -p wayfinder-code --lib real_qualification_is_private_and_preserves_active_selection -- --ignored --nocapture
```

`WF_CODE_TEST_ROOT` selects the same marked disposable directory used by `real_backend`, so the tests can reuse one downloaded runtime. `WF_CODE_QUALIFICATION_MANIFEST` optionally supplies the absolute path of a candidate channel JSON file. This input exists only in the ignored test, is validated by the production manifest decoder, and never changes the active runtime selection or the embedded recipe. It allows maintainers to qualify a newer channel release without modifying or rebuilding app-version pins. Run qualification on each supported platform before approving its artifacts; the fixture tests Python semantic operations, not every language/SDK.

After the manifest passes local validation, publishing it requires a deliberate distribution-worker deployment only. It requires no Wayfinder app version bump, tag, app release, gateway deployment, backend repackaging or agent restart. An incompatible integration contract instead requires a deliberate Wayfinder integration update. Publishing/deploying is never part of validation.
