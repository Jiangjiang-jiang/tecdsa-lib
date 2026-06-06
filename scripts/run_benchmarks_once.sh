#!/usr/bin/env bash
set -euo pipefail

# Run each ZK proof benchmark exactly ONCE with wall-clock timing.
# Uses Criterion's --test mode (runs fixture + one iteration, no stats).

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="docs/benchmarks"
mkdir -p "$OUT_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULT="$OUT_DIR/bench-once-${TIMESTAMP}.txt"

echo "=== Single-run ZK benchmark: $TIMESTAMP ===" | tee "$RESULT"
echo "Machine: $(uname -n) $(uname -m)" | tee -a "$RESULT"
echo "Rust: $(rustc --version)" | tee -a "$RESULT"
echo "" | tee -a "$RESULT"

# Build once
cargo bench -p tecdsa-bench --bench zk_proofs --no-run 2>&1 | tail -1

# Get all benchmark names
NAMES=$(cargo bench -p tecdsa-bench --bench zk_proofs -- --test --list 2>&1 | grep '^zk/' | sed 's/: benchmark$//')

for name in $NAMES; do
    start_ns=$(date +%s%N)
    cargo bench -p tecdsa-bench --bench zk_proofs -- --test "$name" > /dev/null 2>&1
    end_ns=$(date +%s%N)
    elapsed_us=$(( (end_ns - start_ns) / 1000 ))
    printf "%-60s %12d us\n" "$name" "$elapsed_us" | tee -a "$RESULT"
done

echo "" | tee -a "$RESULT"
echo "=== Done ===" | tee -a "$RESULT"
