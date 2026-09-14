#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

printf '==> Checking formatting\n'
cargo fmt --check

printf '==> Checking workspace\n'
cargo check --workspace

printf '==> Linting workspace\n'
cargo clippy --workspace --all-targets -- -D warnings

printf '==> Testing workspace\n'
cargo test --workspace
