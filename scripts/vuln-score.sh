#!/usr/bin/env bash
# Turn a Trivy JSON report into a readable score. Informational: the pass/fail gate is the Trivy HIGH/CRITICAL scan.
#
#   trivy image --format json --ignore-unfixed -o trivy.json lanwarden:latest && scripts/vuln-score.sh trivy.json
#
# Score = max(0, 100 - (10*CRITICAL + 5*HIGH + 2*MEDIUM + 1*LOW)); 100 means no known fixable vulnerability.
# The weights are this project's own choice, not a standard. Also appended to $GITHUB_STEP_SUMMARY in CI.
set -euo pipefail

report=${1:?usage: vuln-score.sh trivy.json}

out=$(jq -r '
  [.Results[]?.Vulnerabilities[]?] as $v
  | def n($s): [$v[] | select(.Severity == $s)] | length;
    (n("CRITICAL")) as $c | (n("HIGH")) as $h | (n("MEDIUM")) as $m | (n("LOW")) as $l
  | ([$v[].CVSS[]?.V3Score // empty] | max // 0) as $cvss
  | [(100 - (10*$c + 5*$h + 2*$m + $l)), 0] | max as $score
  | "Vulnerability score: \($score)/100  (CRITICAL \($c), HIGH \($h), MEDIUM \($m), LOW \($l); highest CVSS v3 \($cvss))"
' "$report")

echo "$out"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '### Image scan\n%s\n' "$out" >> "$GITHUB_STEP_SUMMARY"; fi
