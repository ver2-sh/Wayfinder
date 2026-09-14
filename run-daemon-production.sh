#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

"$repo_root/build-production.sh"
printf '==> Starting Wayfinder daemon (production)\n'
exec "$repo_root/target/release/wayfinder" daemon "$@"
