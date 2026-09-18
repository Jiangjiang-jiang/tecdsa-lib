#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ALL_TABLES=(zk mta dkg sign twoparty)

usage() {
    cat <<'EOF'
tecdsa-lib evaluation artifact — reproduces the measured numbers of the paper.

Usage:
  bash scripts/run_artifact.sh sizes            # step 1: sizes + communication
  bash scripts/run_artifact.sh times <name>...  # step 2: benchmark the timings
  bash scripts/run_artifact.sh tables <name>... # step 3: render the tables
  bash scripts/run_artifact.sh list             # what each table needs
  bash scripts/run_artifact.sh help

Tables (<name>, or `all` for every one of them):
  zk        ZK proofs on the critical path   (benchmark: zk_proofs)
  mta       per-instance MtA conversions     (benchmarks: primitives, zk_proofs)
  dkg       multi-party key generation       (benchmark: multiparty, DKG sweep)
  sign      multi-party signing              (benchmark: multiparty, sign sweep)
  twoparty  two-party key generation+signing (benchmark: twoparty)

Steps:
  sizes   measures the proof and communication sizes (covers every table)
  times   benchmarks the timings of the named tables
  tables  renders the named tables

Environment:
  TECDSA_BENCH_DKG_CONFIGS      DKG (n,t) pairs, `n:t,...`  (default 2:2,3:3,7:7,11:11,15:15,20:20)
  TECDSA_BENCH_SIGN_N           presign/sign party count    (default 20)
  TECDSA_BENCH_SIGN_THRESHOLDS  signing thresholds, `t,...`  (default 2,3,7,11,20)
  TECDSA_BENCH_RUNS             protocol executions per (phase, config);
                                unset = adaptive (~10 samples), 1 = fastest
  TECDSA_BENCH_PROTOCOLS        protocol subset for `sizes`; unset = all
  TECDSA_BENCH_JOBS             worker threads for `sizes`; unset = CPU count
  BENCH_ARGS                    extra Criterion flags (default --noplot)
  RESULTS_DIR                   output directory (default results/<timestamp>)

Set TECDSA_BENCH_DKG_CONFIGS= or TECDSA_BENCH_SIGN_THRESHOLDS= (empty) to skip
that sweep.

Examples:
  bash scripts/run_artifact.sh sizes
  bash scripts/run_artifact.sh times zk && bash scripts/run_artifact.sh tables zk
  TECDSA_BENCH_RUNS=1 bash scripts/run_artifact.sh times all
  TECDSA_BENCH_SIGN_N=7 TECDSA_BENCH_SIGN_THRESHOLDS=2,7 \
      bash scripts/run_artifact.sh times sign

Every command is echoed with its output and captured under results/<timestamp>/.
EOF
}

# ─────────────────────────────────────────────────────────────────────────
# Table metadata: generator, description, and the benchmarks it reads.
# Mirrors the sources documented at the top of each generator.
# ─────────────────────────────────────────────────────────────────────────
table_py() {
    case "$1" in
        zk) echo build_zk_table.py ;;
        mta) echo build_mta_table.py ;;
        dkg) echo build_dkg_table.py ;;
        sign) echo build_sign_table.py ;;
        twoparty) echo build_twoparty_table.py ;;
        *) return 1 ;;
    esac
}

table_desc() {
    case "$1" in
        zk) echo "ZK proofs on the critical path: prove/verify from zk_proofs, size from zk_once" ;;
        mta) echo "per-instance MtA conversions: phases from primitives plus zk/class_group/r_enc, comm from protocol_once" ;;
        dkg) echo "multi-party key generation: setup/dkg/aux-info from multiparty" ;;
        sign) echo "multi-party signing: presign/online-sign from multiparty, comm from protocol_once" ;;
        twoparty) echo "two-party key generation and signing: twoparty benches, comm from protocol_once" ;;
        *) return 1 ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────
COMMAND=""
TABLES=()

while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help | help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option '$1' (try: bash scripts/run_artifact.sh help)" >&2
            exit 1
            ;;
        *)
            if [ -z "$COMMAND" ]; then
                COMMAND="$1"
            else
                TABLES+=("$1")
            fi
            shift
            ;;
    esac
done

case "${COMMAND:-}" in
    sizes | list) ;;
    times | tables)
        if [ "${#TABLES[@]}" -eq 0 ]; then
            echo "error: '$COMMAND' needs at least one table name (or 'all'); try: bash scripts/run_artifact.sh list" >&2
            exit 1
        fi
        if [ "${TABLES[0]}" = all ] && [ "${#TABLES[@]}" -eq 1 ]; then
            TABLES=("${ALL_TABLES[@]}")
        fi
        for t in "${TABLES[@]}"; do
            if ! table_py "$t" > /dev/null; then
                echo "error: unknown table '$t' (expected: ${ALL_TABLES[*]}, all)" >&2
                exit 1
            fi
        done
        ;;
    "")
        usage
        exit 1
        ;;
    *)
        echo "error: unknown command '$COMMAND' (expected: sizes, times, tables, list)" >&2
        exit 1
        ;;
esac

if [ "$COMMAND" = list ]; then
    printf 'Tables:\n\n'
    for t in "${ALL_TABLES[@]}"; do
        printf '  %-9s %s\n' "$t" "$(table_desc "$t")"
        printf '  %-9s generator: %s\n\n' "" "$(table_py "$t")"
    done
    cat <<'EOF'
Order of work:
  bash scripts/run_artifact.sh sizes            # once, covers every table
  bash scripts/run_artifact.sh times <name>...  # benchmark the timings
  bash scripts/run_artifact.sh tables <name>... # render the tables
EOF
    exit 0
fi

# `cargo bench` forwards these to Criterion. Plotting is off by default because
# it costs minutes per suite and the generators read the JSON estimates.
BENCH_ARGS="${BENCH_ARGS:---noplot}"

# An empty value for these four is a reviewer typo rather than an instruction;
# unset them so the benchmark crate applies its documented default (an empty
# TECDSA_BENCH_SIGN_N or TECDSA_BENCH_RUNS would otherwise abort the run).
for var in TECDSA_BENCH_SIGN_N TECDSA_BENCH_RUNS TECDSA_BENCH_PROTOCOLS TECDSA_BENCH_JOBS; do
    if [ -n "${!var+set}" ] && [ -z "${!var}" ]; then
        unset "$var"
    fi
done

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${RESULTS_DIR:-$REPO_ROOT/results/$TIMESTAMP}"
RAW_DIR="$RESULTS_DIR/raw"
TABLE_DIR="$RESULTS_DIR/tables"
mkdir -p "$RAW_DIR" "$TABLE_DIR"
LOG="$RESULTS_DIR/run.log"

# Mirror everything (stdout+stderr, including the commands echoed by `run`) to
# the log while keeping it on the terminal, so a second shell attached with
# `docker exec -it <container> bash` can follow the same stream in the log file.
exec > >(tee -a "$LOG") 2>&1

# Render one sweep variable for the run header: its value, or what the
# benchmark crate will do when it is unset / set-but-empty.
show_var() {
    local name="$1" unset_note="$2" empty_note="${3:-}"
    if [ -z "${!name+set}" ]; then
        printf '<unset: %s>' "$unset_note"
    elif [ -z "${!name}" ]; then
        printf '<empty: %s>' "${empty_note:-$unset_note}"
    else
        printf '%s' "${!name}"
    fi
}

section() {
    printf '\n══════════════════════════════════════════════════════════════════\n'
    printf '  %s\n' "$1"
    printf '══════════════════════════════════════════════════════════════════\n'
}

TIMINGS=()
FAILURES=()

# Echo the command, run it, tee its output to $RAW_DIR/<name>.txt, and record
# the wall-clock duration for the closing summary.
run() {
    local name="$1"
    shift
    local outfile="$RAW_DIR/${name}.txt"
    local start=$SECONDS

    printf '\n$ %s\n' "$*"
    local status=0
    if ! "$@" 2>&1 | tee "$outfile"; then
        status=${PIPESTATUS[0]}
    fi

    local elapsed=$(( SECONDS - start ))
    if [ "$status" -eq 0 ]; then
        printf -- '--- %s: ok in %ds (%s)\n' "$name" "$elapsed" "$outfile"
        TIMINGS+=("$(printf '%-24s %6ds  ok' "$name" "$elapsed")")
    else
        printf -- '--- %s: FAILED (exit %d) after %ds (%s)\n' "$name" "$status" "$elapsed" "$outfile"
        TIMINGS+=("$(printf '%-24s %6ds  FAILED (exit %d)' "$name" "$elapsed" "$status")")
        FAILURES+=("$name")
    fi
    return 0
}

have_artifacts() {  # <dir> -- true when the one-shot binaries wrote something
    compgen -G "$1/*.tsv" > /dev/null
}

# ─────────────────────────────────────────────────────────────────────────
# What do the requested tables need?
# ─────────────────────────────────────────────────────────────────────────
want_zk=0 want_mta=0 want_dkg=0 want_sign=0 want_twoparty=0
for t in "${TABLES[@]:-}"; do
    case "$t" in
        zk) want_zk=1 ;;
        mta) want_mta=1 ;;
        dkg) want_dkg=1 ;;
        sign) want_sign=1 ;;
        twoparty) want_twoparty=1 ;;
    esac
done

NOTES=()

if [ "$COMMAND" = times ]; then
    # The multiparty suite runs a DKG sweep and a presign/sign sweep, each gated
    # by its own variable. The real protocol executions happen outside
    # Criterion's filter, so an unused sweep can only be switched off through
    # the environment. Narrow it to the phase the requested tables report,
    # unless the reviewer set the variable explicitly.
    if [ "$want_dkg" = 1 ] && [ "$want_sign" = 0 ] && [ -z "${TECDSA_BENCH_SIGN_THRESHOLDS+set}" ]; then
        export TECDSA_BENCH_SIGN_THRESHOLDS=
        NOTES+=("dkg table: presign/sign sweep switched off (TECDSA_BENCH_SIGN_THRESHOLDS=); set it to override")
    fi
    if [ "$want_sign" = 1 ] && [ "$want_dkg" = 0 ] && [ -z "${TECDSA_BENCH_DKG_CONFIGS+set}" ]; then
        export TECDSA_BENCH_DKG_CONFIGS=
        NOTES+=("sign table: DKG sweep switched off (TECDSA_BENCH_DKG_CONFIGS=); set it to override")
    fi
fi

# zk_proofs: the zk table needs every proof relation, the mta table only the CL
# proof measured outside the MtA cycle (see build_mta_table.py ROWS).
ZK_FILTER=""
need_zk_bench=0
if [ "$want_zk" = 1 ]; then
    need_zk_bench=1
elif [ "$want_mta" = 1 ]; then
    need_zk_bench=1
    ZK_FILTER="zk/class_group/r_enc"
    NOTES+=("mta table: zk_proofs filtered to $ZK_FILTER (the only proof it reads)")
fi

# ─────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────
case "$COMMAND" in
    sizes) section "tecdsa-lib artifact — sizes and communication — $TIMESTAMP" ;;
    times) section "tecdsa-lib artifact — times for: ${TABLES[*]} — $TIMESTAMP" ;;
    tables) section "tecdsa-lib artifact — tables: ${TABLES[*]} — $TIMESTAMP" ;;
esac

cat <<EOF
Repo:      $REPO_ROOT
Commit:    $(git rev-parse HEAD 2>/dev/null || echo "${SUBMISSION_COMMIT:-n/a (no git metadata in image)}")
Machine:   $(uname -srm), $(nproc) CPU(s)
Rust:      $(rustc --version)
Python:    $(python3 --version)
Results:   $RESULTS_DIR
Log:       $LOG
EOF

if [ "$COMMAND" != tables ]; then
    cat <<EOF

Benchmark configuration (env, effective for this run):
  TECDSA_BENCH_DKG_CONFIGS      = $(show_var TECDSA_BENCH_DKG_CONFIGS "2:2,3:3,7:7,11:11,15:15,20:20" "skip the DKG sweep")
  TECDSA_BENCH_SIGN_N           = $(show_var TECDSA_BENCH_SIGN_N "20")
  TECDSA_BENCH_SIGN_THRESHOLDS  = $(show_var TECDSA_BENCH_SIGN_THRESHOLDS "2,3,7,11,20" "skip the presign/sign sweep")
  TECDSA_BENCH_RUNS             = $(show_var TECDSA_BENCH_RUNS "adaptive")
  TECDSA_BENCH_PROTOCOLS        = $(show_var TECDSA_BENCH_PROTOCOLS "all protocols")
  TECDSA_BENCH_JOBS             = $(show_var TECDSA_BENCH_JOBS "$(nproc) (CPU count)")
  BENCH_ARGS                    = $BENCH_ARGS
EOF
fi

for note in "${NOTES[@]:-}"; do
    [ -n "$note" ] && printf 'Note: %s\n' "$note"
done

# ─────────────────────────────────────────────────────────────────────────
# sizes — one-shot runs: serialized proof sizes and per-party communication
# ─────────────────────────────────────────────────────────────────────────
if [ "$COMMAND" = sizes ]; then
    section "One-shot measurements (shared by every table)"
    run zk_once cargo run --release -p tecdsa-bench --bin zk_once
    run protocol_once cargo run --release -p tecdsa-bench --bin protocol_once
fi

# ─────────────────────────────────────────────────────────────────────────
# times — Criterion suites needed by the requested tables
# ─────────────────────────────────────────────────────────────────────────
if [ "$COMMAND" = times ]; then
    section "Criterion benchmarks for: ${TABLES[*]}"

    if [ "$want_dkg" = 1 ] || [ "$want_sign" = 1 ]; then
        # shellcheck disable=SC2086  # BENCH_ARGS is an intentional word list
        run bench-multiparty cargo bench -p tecdsa-bench --bench multiparty -- $BENCH_ARGS
    fi
    if [ "$want_mta" = 1 ]; then
        # shellcheck disable=SC2086
        run bench-primitives cargo bench -p tecdsa-bench --bench primitives -- $BENCH_ARGS
    fi
    if [ "$want_twoparty" = 1 ]; then
        # shellcheck disable=SC2086
        run bench-twoparty cargo bench -p tecdsa-bench --bench twoparty -- $BENCH_ARGS
    fi
    if [ "$need_zk_bench" = 1 ]; then
        # shellcheck disable=SC2086
        run bench-zk_proofs cargo bench -p tecdsa-bench --bench zk_proofs -- $BENCH_ARGS $ZK_FILTER
    fi
fi

# ─────────────────────────────────────────────────────────────────────────
# tables — render the requested tables from the recorded measurements
# ─────────────────────────────────────────────────────────────────────────
if [ "$COMMAND" = tables ]; then
    section "Table generation from the measurements in target/"

    # The generators live in scripts/ in current trees and at the repo root in
    # older ones; accept either so the artifact is layout-independent.
    find_generator() {
        local name="$1" candidate
        for candidate in "scripts/$name" "$name"; do
            if [ -f "$REPO_ROOT/$candidate" ]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done
        return 1
    }

    if ! have_artifacts target/zk_sizes || ! have_artifacts target/comm_online; then
        printf '\nWarning: target/zk_sizes or target/comm_online is empty, so the Size and\n'
        printf 'Comm. columns will be "--". Record them with (once, covers every table):\n'
        printf '    bash scripts/run_artifact.sh sizes\n'
    fi
    if [ ! -d target/criterion ]; then
        printf '\nWarning: target/criterion does not exist, so every timing column will be\n'
        printf '"--". Measure the timings first, e.g.:\n'
        printf '    bash scripts/run_artifact.sh times %s\n' "${TABLES[0]}"
    fi

    for t in "${TABLES[@]}"; do
        name="$(table_py "$t")"
        if ! generator="$(find_generator "$name")"; then
            printf -- '--- table %s: generator %s not found (skipped)\n' "$t" "$name"
            continue
        fi
        tex="$TABLE_DIR/${t}.tex"
        err="$TABLE_DIR/${t}.err"
        printf '\n$ python3 %s\n' "$generator"
        if python3 "$generator" > "$tex" 2> "$err"; then
            cat "$tex"
            printf -- '--- table %s: ok (%s)\n' "$t" "$tex"
            TIMINGS+=("$(printf '%-24s         ok' "table $t")")
        else
            cat "$err"
            printf -- '--- table %s: FAILED (%s)\n' "$t" "$err"
            TIMINGS+=("$(printf '%-24s         FAILED' "table $t")")
            FAILURES+=("table $t")
        fi
    done
fi

# ─────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────
section "Summary"
printf 'Steps:\n'
for line in "${TIMINGS[@]:-}"; do
    [ -n "$line" ] && printf '  %s\n' "$line"
done
printf '\nTotal wall-clock: %ds\n' "$SECONDS"

if [ "$COMMAND" = tables ]; then
    printf '\nGenerated LaTeX tables:\n'
    if compgen -G "$TABLE_DIR/*.tex" > /dev/null; then
        for tex in "$TABLE_DIR"/*.tex; do
            printf '  %s (%s lines)\n' "$tex" "$(wc -l < "$tex")"
        done
    else
        printf '  (none)\n'
    fi
fi

printf '\nRaw command output:    %s\n' "$RAW_DIR"
printf 'Full session log:      %s\n' "$LOG"
printf 'Measurements in target/: criterion (timings), zk_sizes (proof sizes), comm_online (communication)\n'

if [ "${#FAILURES[@]}" -gt 0 ]; then
    printf '\n%d step(s) FAILED: %s\n' "${#FAILURES[@]}" "${FAILURES[*]}"
    exit 1
fi

case "$COMMAND" in
    sizes)
        printf '\nSizes and communication recorded for every table. Next:\n'
        printf '    bash scripts/run_artifact.sh times <name>...   # e.g. zk, or all\n'
        ;;
    times)
        printf '\nTimings recorded. Render the tables with:\n'
        printf '    bash scripts/run_artifact.sh tables %s\n' "${TABLES[*]}"
        ;;
    tables)
        printf '\nTables written to %s\n' "$TABLE_DIR"
        ;;
esac
