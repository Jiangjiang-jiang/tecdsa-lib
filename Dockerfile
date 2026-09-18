# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Evaluation artifact for tecdsa-lib: reproduces the benchmark tables of the paper.
#
# 1. Build (a few minutes: GMP is compiled from source, then ~40 crates):
#      docker build -t tecdsa-artifact .
#
# 2. Get a shell (add -v to keep the results on the host):
#      docker run -it --name tecdsa-eval \
#          -v "$PWD/results:/artifact/results" tecdsa-artifact
#
#    A second shell in the same container, e.g. to watch a long run:
#      docker exec -it tecdsa-eval bash
#
# 3. Inside the container, measure the sizes once, then per table the timings,
#    then render the tables (`list` shows what each table needs, `all` selects
#    every table):
#      bash scripts/run_artifact.sh sizes
#      bash scripts/run_artifact.sh list
#      bash scripts/run_artifact.sh times zk
#      bash scripts/run_artifact.sh tables zk
#
# Every command is echoed with its output and captured under results/<run>/.
#
# The benchmark sweeps are read from the environment at run time (no rebuild),
# so they are set per command rather than baked into the image. Defaults come
# from crates/framework/tecdsa-bench/src/config.rs; override them per run:
#
#   TECDSA_BENCH_DKG_CONFIGS      DKG (n,t) pairs, `n:t,...`  (default 2:2,3:3,7:7,11:11,20:20)
#   TECDSA_BENCH_SIGN_N           presign/sign party count    (default 20)
#   TECDSA_BENCH_SIGN_THRESHOLDS  signing thresholds, `t,...` (default 2,3,7,11,20)
#   TECDSA_BENCH_RUNS             protocol executions per (phase, config);
#                                 unset = adaptive (~10 samples), 1 = fastest
#   TECDSA_BENCH_PROTOCOLS        protocol subset for protocol_once; unset = all
#   TECDSA_BENCH_JOBS             protocol_once worker threads; unset = CPU count
#
#   # per command, inside the container
#   TECDSA_BENCH_SIGN_N=7 TECDSA_BENCH_SIGN_THRESHOLDS=2,7 \
#       bash scripts/run_artifact.sh times sign
#
#   # or for the whole container session
#   docker run -it -e TECDSA_BENCH_RUNS=1 tecdsa-artifact

FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        m4 \
        python3 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
        --component rustfmt --component clippy \
    && rustc --version && cargo --version

WORKDIR /artifact
COPY . .

RUN cargo build --release -p tecdsa-bench --bins \
    && cargo bench -p tecdsa-bench --no-run

ARG SUBMISSION_COMMIT=
ENV SUBMISSION_COMMIT=${SUBMISSION_COMMIT}

RUN printf '%s\n' \
    'cat <<BANNER' \
    'tecdsa-lib evaluation artifact (/artifact)' \
    '  1. bash scripts/run_artifact.sh sizes            # proof sizes + communication (once)' \
    '  2. bash scripts/run_artifact.sh times <name>...  # benchmark the timings' \
    '  3. bash scripts/run_artifact.sh tables <name>... # render the tables' \
    'Tables: zk, mta, dkg, sign, twoparty, all   (bash scripts/run_artifact.sh list)' \
    'Details: bash scripts/run_artifact.sh help' \
    'BANNER' \
    >> /root/.bashrc

CMD ["bash"]
