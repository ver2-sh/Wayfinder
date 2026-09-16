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
user. Reinstall the startup definition if you move the binary. Do not overwrite
an executable while a service owns it; use its lifecycle commands.
