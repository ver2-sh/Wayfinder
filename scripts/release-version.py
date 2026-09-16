#!/usr/bin/env python3
"""Validate an intended stable tag without creating it or contacting GitHub."""
import re
import sys
import tomllib
from pathlib import Path
version = tomllib.loads((Path(__file__).resolve().parent.parent / 'Cargo.toml').read_text())['workspace']['package']['version']
expected = f'v{version}'
tag = sys.argv[1] if len(sys.argv) > 1 else expected
if not re.fullmatch(r'v\d+\.\d+\.\d+', tag) or tag != expected:
    raise SystemExit(f'Release tag {tag!r} must match stable workspace version {expected}')
print(expected)
