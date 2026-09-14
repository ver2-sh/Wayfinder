#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

printf '==> Building Wayfinder (development)\n'
printf '==> For production usage, normally use build-production.sh\n'
cargo build -p wayfinder "$@"
printf '==> Binary: %s\n' "$repo_root/target/debug/wayfinder"
