#!/usr/bin/env bash
# Usage: scripts/coverage.sh <coverprofile> <min-percent>
# Prints per-package statement coverage for the internal/ packages and fails
# if the total is below the threshold. The profile must come from
# `go test -coverpkg=./internal/...` so cross-package tests count.
set -euo pipefail
profile=${1:?coverprofile}
min=${2:?min percent}
go tool cover -func="$profile" | awk -v min="$min" '
  /^total:/ { total = $3; sub("%", "", total); next }
  END {
    printf "coverage (statements, internal/... + policies): %.1f%% (threshold %s%%)\n", total, min
    if (total + 0 < min + 0) { print "coverage: FAIL"; exit 1 }
    print "coverage: ok"
  }'
# Per-package breakdown from the same profile. With -coverpkg every test
# binary reports every block, so blocks are de-duplicated (covered if any
# binary covered them) before aggregating per package.
awk 'NR > 1 {
  key = $1; stmts[key] = $2; if ($3 > 0) hit[key] = 1
} END {
  for (k in stmts) {
    split(k, a, ":"); n = split(a[1], s, "/"); p = s[1]; for (i = 2; i < n; i++) p = p "/" s[i]
    ps[p] += stmts[k]; if (k in hit) ph[p] += stmts[k]
  }
  for (p in ps) printf "  %-55s %5.1f%%\n", p, 100 * ph[p] / ps[p]
}' "$profile" | sort
