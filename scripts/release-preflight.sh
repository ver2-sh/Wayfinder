#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/release-version.py "${1:-$(python3 scripts/release-version.py)}"
./validate.sh
cargo build --release -p wayfinder
python3 scripts/dist-workflow.py --check
python3 scripts/test-dist-bootstrap.py
if command -v actionlint >/dev/null 2>&1; then actionlint; fi
"${DIST:-dist}" generate --check
"${DIST:-dist}" plan --output-format=json > target/release-plan.json
python3 - <<'PYPLAN'
import json
import tomllib
config = tomllib.load(open('dist-workspace.toml', 'rb'))['dist']
assert config['cargo-dist-version'] == '0.33.0'
assert config['cache-builds'] is False
assert config['merge-tasks'] is True
plan = json.load(open('target/release-plan.json'))
assert [release['app_name'] for release in plan['releases']] == ['wayfinder']
rows = plan['ci']['github']['artifacts_matrix']['include']
assert {target for row in rows for target in row['targets']} == {
    'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
    'x86_64-pc-windows-msvc', 'aarch64-apple-darwin', 'x86_64-apple-darwin',
}
assert sum(len(row['targets']) for row in rows) == 5
assert plan['ci']['github']['pr_run_mode'] == 'skip'
assert len([row for row in rows if 'macos' in row['runner']]) == 1
PYPLAN
for script in ./*.sh scripts/*.sh; do bash -n "$script"; done
printf 'Local preflight passed. No tag, release, push, or hosted workflow was created.\n'
