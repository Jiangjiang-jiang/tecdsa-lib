#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="docs/benchmarks"
mkdir -p "$OUT_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
SUMMARY="$OUT_DIR/bench-summary-${TIMESTAMP}.txt"

echo "=== tecdsa-lib benchmark run: $TIMESTAMP ===" | tee "$SUMMARY"
echo "Machine: $(uname -n) $(uname -m)" | tee -a "$SUMMARY"
echo "Rust: $(rustc --version)" | tee -a "$SUMMARY"
echo "" | tee -a "$SUMMARY"

CRITERION_ARGS="--sample-size 10 --nresamples 100 --warm-up-time 1 --measurement-time 1 --noplot --output-format bencher"

run_bench() {
    local name="$1"
    local bench="$2"
    local filter="${3:-}"
    local outfile="$OUT_DIR/${name}-${TIMESTAMP}.txt"

    echo ">>> Running: $name" | tee -a "$SUMMARY"
    local start_s=$SECONDS

    if [ -n "$filter" ]; then
        cargo bench -p tecdsa-bench --bench "$bench" -- $CRITERION_ARGS "$filter" 2>&1 | tee "$outfile"
    else
        cargo bench -p tecdsa-bench --bench "$bench" -- $CRITERION_ARGS 2>&1 | tee "$outfile"
    fi

    local elapsed=$(( SECONDS - start_s ))
    echo "    Completed in ${elapsed}s" | tee -a "$SUMMARY"
    echo "" | tee -a "$SUMMARY"

    grep '^test ' "$outfile" >> "$SUMMARY" 2>/dev/null || true
    echo "" >> "$SUMMARY"
}

MODE="${1:-all}"

case "$MODE" in
    zk-once)
        outfile="$OUT_DIR/zk-once-${TIMESTAMP}.txt"
        echo ">>> Running: zk-once" | tee -a "$SUMMARY"
        local_start=$SECONDS
        cargo run --release -p tecdsa-bench --bin zk_once 2>&1 | tee "$outfile"
        elapsed=$(( SECONDS - local_start ))
        echo "    Completed in ${elapsed}s" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        cat "$outfile" >> "$SUMMARY"
        echo "" >> "$SUMMARY"
        ;;
    protocol-once)
        outfile="$OUT_DIR/protocol-once-${TIMESTAMP}.txt"
        echo ">>> Running: protocol-once" | tee -a "$SUMMARY"
        local_start=$SECONDS
        cargo run --release -p tecdsa-bench --bin protocol_once 2>&1 | tee "$outfile"
        elapsed=$(( SECONDS - local_start ))
        echo "    Completed in ${elapsed}s" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        cat "$outfile" >> "$SUMMARY"
        echo "" >> "$SUMMARY"
        ;;
    once)
        outfile_zk="$OUT_DIR/zk-once-${TIMESTAMP}.txt"
        echo ">>> Running: zk-once" | tee -a "$SUMMARY"
        local_start=$SECONDS
        cargo run --release -p tecdsa-bench --bin zk_once 2>&1 | tee "$outfile_zk"
        elapsed=$(( SECONDS - local_start ))
        echo "    Completed in ${elapsed}s" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        cat "$outfile_zk" >> "$SUMMARY"
        echo "" >> "$SUMMARY"

        outfile_proto="$OUT_DIR/protocol-once-${TIMESTAMP}.txt"
        echo ">>> Running: protocol-once" | tee -a "$SUMMARY"
        local_start=$SECONDS
        cargo run --release -p tecdsa-bench --bin protocol_once 2>&1 | tee "$outfile_proto"
        elapsed=$(( SECONDS - local_start ))
        echo "    Completed in ${elapsed}s" | tee -a "$SUMMARY"
        echo "" | tee -a "$SUMMARY"
        cat "$outfile_proto" >> "$SUMMARY"
        echo "" >> "$SUMMARY"
        ;;
    zk)
        run_bench "zk-proofs" "zk_proofs"
        ;;
    protocol)
        run_bench "primitives" "primitives"
        run_bench "multiparty" "multiparty"
        run_bench "twoparty" "twoparty"
        ;;
    all)
        run_bench "zk-proofs" "zk_proofs"

        run_bench "primitives" "primitives"

        run_bench "multiparty" "multiparty"

        run_bench "twoparty" "twoparty"
        ;;
    *)
        echo "Usage: $0 [once|zk-once|protocol-once|zk|protocol|all]"
        exit 1
        ;;
esac

total_elapsed=$SECONDS
echo "=== Total: ${total_elapsed}s ===" | tee -a "$SUMMARY"
echo ""
echo "Results saved to:"
echo "  $SUMMARY"
echo "  $OUT_DIR/*-${TIMESTAMP}.txt"
