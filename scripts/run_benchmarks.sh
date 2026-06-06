#!/usr/bin/env bash
set -euo pipefail

# Single-iteration benchmark run for all ZK proofs and protocol operations.
# Outputs raw timing to docs/benchmarks/*.txt and a summary table.
#
# Usage:
#   bash scripts/run_benchmarks.sh              # run all (Criterion, slow)
#   bash scripts/run_benchmarks.sh once         # all one-shot (ZK + protocol, fastest)
#   bash scripts/run_benchmarks.sh zk-once      # ZK one-shot timings only
#   bash scripts/run_benchmarks.sh protocol-once # protocol one-shot timings only
#   bash scripts/run_benchmarks.sh zk           # ZK proofs only (Criterion)
#   bash scripts/run_benchmarks.sh protocol     # protocol benchmarks only (Criterion)
#
# Prerequisites:
#   - Rust toolchain (stable)
#   - ~10-30 min depending on hardware (Paillier/CL proofs are heavy)
#
# Profile B parameters (lambda=128, secp256k1):
#   Paillier N=3072, CL |DeltaK|~1827, JL N=3072/k=256, NTilde=3072
#
# ZK proof coverage (110 benchmark functions, 55 proof relations):
#   curve       5/5   Dlog, Ddh, Egexp, Prod, Re
#   pedersen    2/2   PiPrm, PiMod
#   class-grp  19/19  REnc, RKey, RDlCl, REncPc, RPcDl, RDecDl, RClKwlg,
#                      RBint, RComKwlg, RGdecCl, RClDl, RClDlEc, RDdhCl,
#                      RElCl, RPedEc, RAffCom, RMAffDl, RMAffDlEc, RSh
#   paillier   13/13  CorrectKeyNi, HomoElGamal, PiEq, HomoMult, AliceRange,
#                      RangeNi, PdlSlack, PiB, BobExt, NonceConsist, PiA,
#                      Bob, PDL transcript
#   pzk-facade  6/6   Pi_enc, Pi_fac, Pi_mod, Pi_aff_g, Pi_elog, Pi_enc_elg
#   joye-lib    9/9   ZkJlEnc, ZkJlMod, ZkJlCom, ZkQr2k, ZkQr2kDl,
#                      ZkJlEqu, ZkJlAff, ZkJlvCom, ZkJlvEqu
#   evrf        1/1   DLEQ (eval + prove + verify)

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

# Criterion minimum is sample-size=10. Use 10 with minimal warm-up, no plots.
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

    # Extract bencher-format timing lines into summary.
    grep '^test ' "$outfile" >> "$SUMMARY" 2>/dev/null || true
    echo "" >> "$SUMMARY"
}

MODE="${1:-all}"

case "$MODE" in
    zk-once)
        # ─────────────────────────────────────────────────────────────
        # ZK one-shot timings (single optimized prove/verify execution)
        # ─────────────────────────────────────────────────────────────
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
        # ─────────────────────────────────────────────────────────────
        # Protocol one-shot timings (MtA + multiparty + twoparty, once each)
        # ─────────────────────────────────────────────────────────────
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
        # ─────────────────────────────────────────────────────────────
        # All one-shot timings (ZK + protocol, fastest full coverage)
        # ─────────────────────────────────────────────────────────────
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
        # ─────────────────────────────────────────────────────────────
        # ZK proof microbenchmarks only (110 functions across 7 groups)
        # ─────────────────────────────────────────────────────────────
        run_bench "zk-proofs" "zk_proofs"
        ;;
    protocol)
        # ─────────────────────────────────────────────────────────────
        # Protocol-level benchmarks (presign + sign, no DKG)
        # ─────────────────────────────────────────────────────────────
        run_bench "primitives" "primitives"
        run_bench "multiparty" "multiparty"
        run_bench "twoparty" "twoparty"
        ;;
    all)
        # ─────────────────────────────────────────────────────────────
        # 1. ZK proof microbenchmarks (all 7 groups, 110 functions)
        # ─────────────────────────────────────────────────────────────
        run_bench "zk-proofs" "zk_proofs"

        # ─────────────────────────────────────────────────────────────
        # 2. Primitive-level benchmarks (Paillier MtA cycle)
        # ─────────────────────────────────────────────────────────────
        run_bench "primitives" "primitives"

        # ─────────────────────────────────────────────────────────────
        # 3. Multi-party protocol benchmarks (presign + sign)
        # ─────────────────────────────────────────────────────────────
        run_bench "multiparty" "multiparty"

        # ─────────────────────────────────────────────────────────────
        # 4. Two-party protocol benchmarks (presign + sign)
        # ─────────────────────────────────────────────────────────────
        run_bench "twoparty" "twoparty"
        ;;
    *)
        echo "Usage: $0 [once|zk-once|protocol-once|zk|protocol|all]"
        exit 1
        ;;
esac

# ─────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────
total_elapsed=$SECONDS
echo "=== Total: ${total_elapsed}s ===" | tee -a "$SUMMARY"
echo ""
echo "Results saved to:"
echo "  $SUMMARY"
echo "  $OUT_DIR/*-${TIMESTAMP}.txt"
