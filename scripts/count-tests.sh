#!/usr/bin/env bash
# Counts passed/failed/skipped tests (including subtests) for the default
# build (no envtest tag). Usage: scripts/count-tests.sh
set -euo pipefail
go test -count=1 -json ./... | python3 -c '
import json, sys
counts = {"pass": 0, "fail": 0, "skip": 0}
for line in sys.stdin:
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("Test") and e.get("Action") in counts:
        counts[e["Action"]] += 1
print("tests: {pass} passed, {fail} failed, {skip} skipped".format(**counts))
sys.exit(1 if counts["fail"] else 0)'
