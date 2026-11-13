#!/usr/bin/env bash
# Regenerate backend/requirements.txt (exact versions + sha256 hashes for Python 3.14 on Linux, the image's
# platform) from backend/requirements.in. Run it deliberately when you want to update dependencies, then
# review the diff, run the tests and scripts/security-scan.sh. Needs uv (https://docs.astral.sh/uv/).
#   scripts/lock-requirements.sh            # keep the versions already locked where the ranges allow
#   scripts/lock-requirements.sh --upgrade  # take the newest versions the ranges allow
set -euo pipefail
cd "$(dirname "$0")/../backend"
command -v uv >/dev/null || { echo "error: uv is not installed" >&2; exit 1; }
uv pip compile requirements.in --generate-hashes --python-version 3.14 --python-platform linux "$@" -o requirements.txt
