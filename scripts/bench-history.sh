#!/usr/bin/env bash
# bench-history.sh — run cyrius benchmarks and append results to CSV history.
#
# Usage: ./scripts/bench-history.sh
#
# Produces: bench-history.csv with columns:
#   date,commit,bench_name,avg_ns,min_ns,max_ns,iters
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSV="${REPO_ROOT}/bench-history.csv"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'uncommitted')"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Ensure header exists
if [ ! -f "$CSV" ]; then
    echo "date,commit,bench_name,avg_ns,min_ns,max_ns,iters" > "$CSV"
fi

cd "$REPO_ROOT"

# Parse cyrius bench output line format:
#   "  <name>: <n><unit> avg (min=<n><unit> max=<n><unit>) [<iters> iters]"
# where unit is ns | us | ms | s and <n> may be a decimal (cyrius 6.4.x
# emits sub-µs precision, e.g. "3.569us", "33.302us"). A float-aware awk
# pass converts every value to integer nanoseconds; the pre-6.4 integer-only
# sed/bash parser silently dumped raw lines into the numeric columns once
# decimal units arrived (fixed at migration 2.1.8).
echo "Running benchmarks..."
cyrius bench tests/t-ron.bcyr 2>/dev/null | \
    awk -v date="$DATE" -v commit="$COMMIT" -v csv="$CSV" '
        function to_ns(tok,   mul) {
            if      (tok ~ /ns$/) { mul = 1 }
            else if (tok ~ /us$/) { mul = 1000 }
            else if (tok ~ /ms$/) { mul = 1000000 }
            else if (tok ~ /s$/)  { mul = 1000000000 }
            else return -1
            sub(/(ns|us|ms|s)$/, "", tok)
            return int(tok * mul + 0.5)
        }
        /^[[:space:]]+[a-z_]+:[[:space:]].*avg/ {
            name = $1; sub(/:$/, "", name)          # "policy_check:" -> "policy_check"
            avg_t = $2                              # "643ns" / "3.569us"
            min_t = $4; sub(/^\(min=/, "", min_t)   # "(min=611ns" -> "611ns"
            max_t = $5; gsub(/max=|\)/, "", max_t)  # "max=33.302us)" -> "33.302us"
            iters = $6; gsub(/[^0-9]/, "", iters)   # "[100000" -> "100000"
            avg = to_ns(avg_t); min = to_ns(min_t); max = to_ns(max_t)
            if (avg < 0 || min < 0 || max < 0) next
            printf "%s,%s,%s,%d,%d,%d,%s\n", date, commit, name, avg, min, max, iters >> csv
            printf "  %-25s avg=%-9s min=%-9s max=%-10s iters=%s\n", name, avg_t, min_t, max_t, iters
        }
    '

echo ""
echo "Results appended to bench-history.csv"
