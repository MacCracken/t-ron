#!/usr/bin/env bash
# bench-history.sh — run benchmarks and append results to CSV history.
#
# Usage: ./scripts/bench-history.sh [optional criterion args]
#
# Produces: benches/history.csv with columns:
#   date,commit,bench_name,time_ns
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CSV="${REPO_ROOT}/benches/history.csv"
COMMIT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo 'uncommitted')"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Ensure header exists
if [ ! -f "$CSV" ]; then
    echo "date,commit,bench_name,time_ns" > "$CSV"
fi

echo "Running benchmarks..."
cargo bench --bench pipeline -- --output-format=bencher 2>/dev/null | \
    grep '^test ' | \
    while IFS= read -r line; do
        # Parse bencher output: "test <name> ... bench:   <time> ns/iter (+/- <var>)"
        name=$(echo "$line" | sed 's/^test \(.*\) \.\.\. bench:.*/\1/' | xargs)
        time_ns=$(echo "$line" | sed 's/.*bench:\s*\([0-9,]*\).*/\1/' | tr -d ',')
        if [ -n "$name" ] && [ -n "$time_ns" ]; then
            echo "${DATE},${COMMIT},${name},${time_ns}" >> "$CSV"
            printf "  %-40s %'d ns/iter\n" "$name" "$time_ns"
        fi
    done

echo ""
echo "Results appended to benches/history.csv"
