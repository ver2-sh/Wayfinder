# Release maintenance

The repository is private and unreleased. This configuration is a foundation, not
an accessible public download channel. Do not change visibility or publish a tag
as a validation step. Ordinary future users need neither GitHub accounts/tokens
nor Rust. No update server or telemetry is required.

## Local preflight, before spending Actions minutes

Install upstream [dist 0.33.0](https://axodotdev.github.io/cargo-dist/), and use
Python 3.11+ and the Rust toolchain. Run from a clean checkout:

```sh
./scripts/release-preflight.sh
# Existing integration exercise, using only disposable identities:
cargo build -p wayfinder -p wayfinder-gateway
python3 -m venv /tmp/wayfinder-validation
/tmp/wayfinder-validation/bin/pip install cryptography mnemonic websockets
/tmp/wayfinder-validation/bin/python tests/sync_chain.py
# Optional native Linux packaging check (requires musl-tools and the Rust target):
rustup target add x86_64-unknown-linux-musl
dist build --artifacts=local --target=x86_64-unknown-linux-musl
# Generate all installer templates with fake archives; NEVER distribute these:
dist build --artifacts=lies
```

The preflight runs formatting, workspace check, strict Clippy, tests, the normal
release build, exact version validation, deterministic workflow generation check,
dist configuration/plan checks, and shell syntax checks. `DIST=/path/to/dist`
selects a local tool. None of these commands creates a tag/release or runs Actions.
The fake-artifact mode is for inspecting templates only; remove `target/distrib`
afterward. Actual release workflows use fresh hosted workspaces and real builds.

`dist-workspace.toml` selects only the main binary. `scripts/dist-workflow.py`
generates upstream's workflow, then narrows tag triggers, moves global tasks to
Ubuntu 24.04 (Python 3.11+), confines release-write permissions and token environment
to hosting steps, makes planning read-only, and removes the empty announce job.
Run it after changing dist configuration; commit its generated workflow. Upstream
cannot express all these choices, hence `allow-dirty = ["ci"]`; the preflight's
separate `--check` reproduces and compares the complete hardened output. It does
not silently exempt the customized workflow from validation.

## Verified cargo-dist CI bootstrap

cargo-dist remains pinned to 0.33.0. `scripts/dist-workflow.py` replaces every
upstream bootstrap with `scripts/dist-bootstrap.py`. The latter downloads the
exact native prebuilt archive and verifies its SHA-256 against constants committed
in this repository **before** reading/installing the executable. The pins were
recorded from the [0.33.0 release](https://github.com/axodotdev/cargo-dist/releases/tag/v0.33.0),
with downloaded bytes cross-checked against GitHub's asset digests. Initial pin
selection trusts that upstream release; subsequent runs trust the reviewed
repository pins, not newly downloaded checksum files. Version/hash changes require
review together. A mismatch or unsupported runner fails closed.

Linux x64/ARM64 musl, macOS ARM64/Intel and Windows x64 MSVC bootstrap archives are
covered. No remote installer is executed. No dist executable is passed between
jobs: global and host jobs independently download and verify the pinned archive.
The host invokes its verified executable by absolute path, with write permissions
confined to that publishing job and GH_TOKEN supplied only to publishing steps.
This adds no jobs, source compilation, or build caches. Preflight checks the
complete regenerated workflow, forbidden bootstrap/cache paths, permissions,
runner pins and rejection of an intentionally incorrect expected hash.

## Intentional release procedure

1. Set `[workspace.package].version` in `Cargo.toml`, for example `0.2.0`. All
   crates inherit it; run `cargo check --workspace` to refresh `Cargo.lock`.
2. Run the local preflight and integration exercise above. Review release notes,
   signing readiness, privacy and generated installer URLs. Commit via normal
   branch/PR review. Do not debug YAML by repeatedly pushing release tags.
3. Only when deliberately releasing the reviewed commit:
   `git tag v0.2.0` then `git push origin v0.2.0`.
4. The plan job rejects any tag not exactly equal to the stable workspace version
   before matrix builds begin. No force-tag option is used. The workflow triggers
   only on `vMAJOR.MINOR.PATCH` tags; there is no PR, branch, schedule or manual
   trigger. Prerelease publishing is intentionally outside this initial channel.
5. Check the release artifacts and perform native install/update/service smoke
   tests before describing a version as ready for consumers.

Expected assets: five platform archives (Linux x64/ARM64 musl, macOS Intel/Apple
Silicon, Windows x64 MSVC), shell and PowerShell installers, dist manifest and
SHA-256 checksum files. WSL uses the Linux assets. No MSI/package repositories
or package-manager channels are provisioned.

## Cost and native validation

Only intentional tags spend Actions minutes. Both macOS architectures share one
native macOS job; Linux uses one native runner per architecture, avoiding a slow
cross-toolchain bootstrap. Windows uses one MSVC job. Compilation occurs once per
target, and global installer/checksum assembly reuses uploaded archives. There are
no persistent Cargo caches for infrequent releases, no repeated cross-platform
validation jobs, and no empty announce job. Upstream's plan/build/global/host
artifact handoffs remain to preserve its manifest and checksum assembly semantics.
Fail-fast cancels sibling builds on failure.

macOS's SDK/native linker and Windows's MSVC environment require their respective
hosts for final artifacts and signing. Linux musl can be built locally. A Windows
GNU `cargo check` on Linux exercises Windows Rust branches but is not validation
of MSVC linking, Task Scheduler behavior or PowerShell. Task Scheduler arguments
use Windows quote/backslash encoding (including doubling trailing backslashes
before closing quotes), separately from PowerShell single-quoted string encoding.
The principal remains the current user with Interactive logon and Limited run
level. Similarly, inspecting a LaunchAgent is not a macOS lifecycle test. Native smoke tests remain release gates;
do them on available local machines rather than triggering hosted builds merely
to prove configuration. Before release, use a disposable Windows installation to
install/start/status/uninstall the Scheduled Task with both ordinary and spaced
data paths, verifying the daemon uses the intended directory. Check direct update
success under normal policy and failure under managed policy, including executable
restoration, agent restart and unchanged persistent policy. Run the equivalent
LaunchAgent lifecycle on macOS. These native runtime checks were unavailable in
this Linux-only audit pass and remain release gates.

## Artifact trust and public readiness

The release origin is the repository metadata/dist configuration; updater discovery
is centralized in `crates/wayfinder/src/update.rs`, independent of gateways. Later
`usewayfinder.app` can link/redirect users to these assets. An actual hosting change
must update dist hosting and updater source together, including existing receipts;
no mandatory vendor update service is needed. Private GitHub releases are not
anonymous public downloads. No private token is embedded or requested by Wayfinder.
A public repository/release channel is required before the documented consumer
commands work without authentication.

The updater uses axoupdater 0.10.2, its receipt ownership checks and upstream
Windows rename/restore/self-replace support. Its PowerShell subprocess uses
process-scoped `-ExecutionPolicy Bypass`. Ordinary direct installations support
`wayfinder update --check` and `wayfinder update` with explicit confirmation,
without requiring an existing Bypass policy or rerunning the initial installer.
This affects only the child PowerShell session: neither CurrentUser nor
LocalMachine policy is changed, and Wayfinder never calls `Set-ExecutionPolicy`.
MachinePolicy/UserPolicy Group Policy takes precedence. If it blocks execution,
upstream reports the installer failure and restores the previous executable;
Wayfinder attempts to restart a previously running managed agent even on failure.
The error directs users with organizational restrictions to their administrator.
Receipt validation and package-manager ownership protection still apply.

For initial installation, download and inspect the script first, then run
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\wayfinder-installer.ps1`
as shown in the README. This is also process-only and cannot override Group Policy.
See Microsoft's [execution-policy scope and precedence documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).

Downloads trust HTTPS and the release publisher. dist emits SHA-256 sums; its shell
installer verifies embedded archive checksums. **dist 0.33.0's PowerShell installer does not verify archive hashes**;
Windows currently relies on HTTPS, with published sums available for manual
`Get-FileHash -Algorithm SHA256` verification. This upstream limitation must be
reviewed before a broadly advertised Windows release. No custom signature format
or unverified claim of end-to-end signature validation is added.

There are no code-signing/notarization credentials configured. Public macOS and
Windows readiness requires Apple Developer signing/notarization and a Windows
code-signing identity, plus native tests. Use dist's supported signing integration
and build setup hooks when credentials exist; keep them in protected release
secrets, never the repository. Do not disable Gatekeeper, SmartScreen or managed
execution policy. GitHub attestations can be enabled later when repository
visibility/plan support is appropriate; they are not currently claimed or required.
