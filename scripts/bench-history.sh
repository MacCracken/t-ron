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
# where unit is ns | us | ms | s.
to_ns() {
    local raw="$1"
    local num
    num=$(echo "$raw" | sed -E 's/[a-z]+$//')
    local unit
    unit=$(echo "$raw" | sed -E 's/^[0-9]+//')
    case "$unit" in
        ns) echo "$num" ;;
        us) echo $((num * 1000)) ;;
        ms) echo $((num * 1000000)) ;;
        s)  echo $((num * 1000000000)) ;;
        *)  echo "$num" ;;
    esac
}

echo "Running benchmarks..."
cyrius bench tests/t-ron.bcyr 2>/dev/null | \
    grep -E '^\s+\w+:.*avg' | \
    while IFS= read -r line; do
        name=$(echo "$line" | sed -E 's/^\s*([a-z_]+):.*/\1/')
        avg=$(echo  "$line" | sed -E 's/.*:[[:space:]]*([0-9]+(ns|us|ms|s))[[:space:]]avg.*/\1/')
        min=$(echo  "$line" | sed -E 's/.*min=([0-9]+(ns|us|ms|s)).*/\1/')
        max=$(echo  "$line" | sed -E 's/.*max=([0-9]+(ns|us|ms|s)).*/\1/')
        iters=$(echo "$line" | sed -E 's/.*\[([0-9]+) iters\].*/\1/')
        avg_ns=$(to_ns "$avg")
        min_ns=$(to_ns "$min")
        max_ns=$(to_ns "$max")
        echo "${DATE},${COMMIT},${name},${avg_ns},${min_ns},${max_ns},${iters}" >> "$CSV"
        printf "  %-25s avg=%s min=%s max=%s iters=%s\n" "$name" "$avg" "$min" "$max" "$iters"
    done

echo ""
echo "Results appended to bench-history.csv"
