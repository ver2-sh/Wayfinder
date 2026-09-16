#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/release-version.py "${1:-$(python3 scripts/release-version.py)}"
./validate.sh
cargo build --release -p wayfinder
python3 scripts/dist-workflow.py --check
"${DIST:-dist}" generate --check
"${DIST:-dist}" plan --output-format=json > target/release-plan.json
python3 - <<'PYPLAN'
import json
plan = json.load(open('target/release-plan.json'))
assert [release['app_name'] for release in plan['releases']] == ['wayfinder']
rows = plan['ci']['github']['artifacts_matrix']['include']
assert sum(len(row['targets']) for row in rows) == 5
assert len([row for row in rows if 'macos' in row['runner']]) == 1
PYPLAN
for script in ./*.sh scripts/*.sh; do bash -n "$script"; done
printf 'Local preflight passed. No tag, release, push, or hosted workflow was created.\n'
