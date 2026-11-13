#!/usr/bin/env bash
# Automated security and quality checks in one command. A tool that is not installed is reported as
# SKIPPED (never silently passed); the exit status is non-zero if any check that did run failed.
#
#   scripts/security-scan.sh
#   FUZZ_EXAMPLES=300 scripts/security-scan.sh         # heavier API fuzzing (default 100 per endpoint)
#   RUN_ZAP=1 scripts/security-scan.sh                  # also an OWASP ZAP baseline scan of a throwaway container
#
# Dev tools:  pip install -r backend/requirements-dev.txt   (pytest-cov, ruff, bandit, pip-audit, schemathesis, uv for semgrep)
# Optional:   gitleaks (or docker/podman to run it), trivy (image scan), docker or podman (ZAP, trivy)
set -uo pipefail
cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}
failed=0
skipped=()

step() { printf '\n== %s\n' "$1"; }
ok()   { echo "   ok"; }
bad()  { echo "   FAILED"; failed=1; }
skip() { echo "   SKIPPED: $1"; skipped+=("$1"); }
py_has() { "$PY" -c "import $1" >/dev/null 2>&1; }

step "tests + coverage floor (90%)"
if py_has pytest_cov; then (cd backend && "$PY" -m pytest -q -p no:cacheprovider --cov=app --cov-fail-under=90) && ok || bad
else skip "pytest-cov not installed"; fi

step "ruff: security (S), bugbear (B), pyflakes (F), pyupgrade (UP)"
if py_has ruff; then
  (cd backend && "$PY" -m ruff check app tests --select F,E9,B,S,UP --ignore S101,S105,S106,S311,B008,UP017,UP042 --line-length 140) && ok || bad
else skip "ruff not installed"; fi

step "bandit (medium and above)"
if py_has bandit; then (cd backend && "$PY" -m bandit -q -r app -ll) && ok || bad; else skip "bandit not installed"; fi

step "semgrep (python, OWASP top ten, typescript, react rules; rules are fetched from semgrep.dev, nothing is uploaded)"
# semgrep-core segfaults on Python 3.15, so it runs in its own 3.14 via uvx; lift once semgrep supports 3.15
if command -v uvx >/dev/null; then uvx --python 3.14 semgrep scan --config p/python --config p/owasp-top-ten --config p/typescript --config p/react --metrics=off --error --quiet backend/app frontend/src && ok || bad
else skip "uvx not installed (pip install -r backend/requirements-dev.txt)"; fi

step "gitleaks (secrets in the working tree and, in a git checkout, its history)"
GITLEAKS_IMAGE=ghcr.io/gitleaks/gitleaks:v8.30.1
if command -v gitleaks >/dev/null; then
  if [ -d .git ]; then gitleaks detect --redact --no-banner -s . && ok || bad; else gitleaks detect --no-git --redact --no-banner -s . && ok || bad; fi
elif [ -n "$(command -v docker || command -v podman || true)" ]; then
  E=$(command -v docker || command -v podman)
  "$E" run --rm -v "$PWD:/repo:ro,Z" "$GITLEAKS_IMAGE" detect $([ -d .git ] || echo --no-git) --redact --no-banner -s /repo && ok || bad
else skip "gitleaks (or docker/podman to run it) not available"; fi

step "pip-audit (backend requirements)"
if py_has pip_audit; then (cd backend && "$PY" -m pip_audit -r requirements.txt) && ok || bad; else skip "pip-audit not installed"; fi

step "npm audit (frontend, moderate and above)"
if command -v npm >/dev/null; then (cd frontend && npm audit --audit-level=moderate) && ok || bad; else skip "npm not installed"; fi

step "API fuzzing (Schemathesis, ${FUZZ_EXAMPLES:-100} examples per endpoint)"
if py_has schemathesis; then (cd backend && FUZZ_EXAMPLES="${FUZZ_EXAMPLES:-100}" "$PY" -m pytest tests/fuzz_api.py -q -p no:cacheprovider) && ok || bad
else skip "schemathesis not installed"; fi

ENGINE=$(command -v docker || command -v podman || true)

step "container image scan (trivy)"
if command -v trivy >/dev/null && [ -n "$ENGINE" ] && "$ENGINE" image inspect lanwarden:latest >/dev/null 2>&1; then
  trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed lanwarden:latest && ok || bad
  if command -v jq >/dev/null && trivy image -q --ignore-unfixed --format json -o /tmp/lanwarden-trivy.json lanwarden:latest; then
    scripts/vuln-score.sh /tmp/lanwarden-trivy.json; rm -f /tmp/lanwarden-trivy.json
  fi
else skip "trivy or a built lanwarden:latest image is missing (scripts/run-container.sh build)"; fi

step "OWASP ZAP baseline (unauthenticated surface only)"
if [ "${RUN_ZAP:-0}" = 1 ] && [ -n "$ENGINE" ]; then
  "$ENGINE" rm -f lanwarden-zap >/dev/null 2>&1
  "$ENGINE" run -d --name lanwarden-zap --network host -e LANWARDEN_PORT=18080 lanwarden:latest >/dev/null
  for _ in $(seq 1 30); do curl -sf http://127.0.0.1:18080/api/health >/dev/null && break; sleep 1; done
  "$ENGINE" run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:18080 -I && ok || bad
  "$ENGINE" rm -f lanwarden-zap >/dev/null 2>&1
else skip "set RUN_ZAP=1 (needs docker/podman and a built image); it pulls a large image"; fi

printf '\n== summary\n'
[ ${#skipped[@]} -gt 0 ] && printf '   skipped: %s\n' "${skipped[@]}"
if [ "$failed" -eq 0 ]; then echo "   all checks that ran passed"; else echo "   ONE OR MORE CHECKS FAILED"; fi
exit "$failed"
