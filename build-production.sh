#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

printf '==> Building Wayfinder (production)\n'
cargo build --release -p wayfinder "$@"
printf '==> Binary: %s\n' "$repo_root/target/release/wayfinder"
