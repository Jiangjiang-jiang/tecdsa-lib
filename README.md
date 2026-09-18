# tecdsa-lib

A Rust implementation and benchmark suite for *SoK: Threshold ECDSA from Theory to Practice*. The experiments cover MtA, zero-knowledge proofs, distributed key generation, and offline/online signing in Appendix C, Tables 3–6.

Protocol source baseline: `66728da5f47099f3e47755185e6cb6f31a861f48`.

## Protocols

- **Multi-party:** GGN16, GG18, LN18, CGGMP20, DKLs23, XAL23, WMY23, TX25, JTX25, WMC24, LLZ25.
- **Two-party:** Lin17, KGG24, XAL21, and ABC24.

## Layout

```text
tecdsa-lib/
|-- crates/
|   |-- core/        base types, curves, big integers
|   |-- primitives/  cryptographic primitives and proofs
|   |-- framework/   protocol execution and benchmarks
|   |-- protocols/   protocol implementations and tests
|   `-- tecdsa/      public library interface
|-- scripts/        benchmark runner and LaTeX table generators
|-- tests/vectors/  wire-format test vectors
|-- vendor/         patched dependencies
`-- Dockerfile      build and runtime environment
```

## Build

Run commands from the repository root. Choose Docker or a native build, then use the same environment for testing, measurements, and table generation.

### Dependencies

Building on Linux requires Bash and either Docker or Rust stable with a C/C++ compiler, Make, and m4. Git records the source revision, while Python 3 generates tables using only its standard library. Cargo builds GMP from bundled sources.

The paper used an Intel Core i9-12900K with 64 GB RAM on Arch Linux. Experiments use CPU computation and require no external dataset or GPU. Internet access is needed to download the image, toolchain, and dependencies during installation.

### Build with Docker

On the host, build the local image `tecdsa-artifact`, which includes source code, dependencies, and precompiled benchmarks:

```bash
# Build the image and record the source commit in it.
docker build --build-arg SUBMISSION_COMMIT="$(git rev-parse HEAD)" -t tecdsa-artifact .

# Keep logs, tables, and exported measurements on the host.
export RESULTS_DIR="$PWD/results/ae-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RESULTS_DIR"

# Enter the environment used for all commands below.
docker run -it --name tecdsa-eval -v "$RESULTS_DIR:/artifact/results" tecdsa-artifact
```

Build completion does not run the experiments. Continue inside the container, keeping it for the whole evaluation so that subsequent commands can read the measurements in its target directory.

To resume after leaving the container, run this on the host:

```bash
docker start -ai tecdsa-eval
```

### Build without Docker

On Debian/Ubuntu with rustup installed, use the following instead of the Docker steps and continue on the host:

```bash
sudo apt-get update
sudo apt-get install -y build-essential m4 python3 curl git ca-certificates
rustup toolchain install stable --profile minimal

export RUSTUP_TOOLCHAIN=stable
unset CARGO_TARGET_DIR

cargo build --locked --release -p tecdsa-bench --bins
cargo bench --locked -p tecdsa-bench --no-run
```

## Tests

Use the existing DKLs23 test to exercise DKG, presigning, signing, and signature verification with a 2-of-3 signing threshold:

```bash
cargo test --locked --release -p tecdsa-dkls23 --test integration test_dkls23_full_sign_2_of_3 -- --exact
```

The test should report one pass and zero failures. In a local run, execution took under a second after compilation. This checks the installation and one complete protocol execution, not the performance results.

## Benchmarks

View available commands, table names, and configuration options:

```bash
bash scripts/run_artifact.sh help
```

Measurements use fixed paths under target, so keep Cargo's default target directory and start from a fresh container or checkout. The commands below keep logs and tables in a single results directory:

```bash
unset CARGO_TARGET_DIR
# Inside Docker, this is the directory mounted from the host.
export RESULTS_DIR="${RESULTS_DIR:-$PWD/results}"
mkdir -p "$RESULTS_DIR"

# Paper configurations, with t equal to the number of required signers.
export TECDSA_BENCH_DKG_CONFIGS=2:2,3:3,7:7,11:11,20:20
export TECDSA_BENCH_SIGN_N=20
export TECDSA_BENCH_SIGN_THRESHOLDS=2,3,7,11,20
export TECDSA_BENCH_JOBS=1 BENCH_ARGS=--noplot
unset TECDSA_BENCH_PROTOCOLS
```

### Sizes and communication

Run this once per configuration to record proof sizes and communication, together with single-run timings. It writes TSV measurements under target and command output under the results directory.

```bash
bash scripts/run_artifact.sh sizes
```

### Timings

Choose one of the following execution counts. It applies to each protocol phase and configuration, while setup, MtA, and ZK measurements use Criterion's own sampling.

For one protocol execution:

```bash
export TECDSA_BENCH_RUNS=1
bash scripts/run_artifact.sh times all
```

For ten executions per phase and configuration, as required for comparison with the paper:

```bash
export TECDSA_BENCH_RUNS=10
bash scripts/run_artifact.sh times all
```

Each step reports its elapsed time and records the command output. Check the logs for failures before interpreting any tables, since a protocol worker can panic without causing the process to return an error:

```bash
# No output is expected from this check.
grep -nE 'panicked|FAILED|^error:' "$RESULTS_DIR"/raw/*.txt "$RESULTS_DIR/run.log" || true
```

### Paper reproduction

To reproduce a selected table, set the run count above and use its timing command instead of the full run. Sizes and communication are shared across tables, and the LaTeX files are generated in the next section.

- **Table 3:** total time and communication for one MtA conversion, summed over both parties. The output is mta.tex.

  ```bash
  bash scripts/run_artifact.sh times mta
  ```

- **Table 4:** proving time, verification time, and serialized size of MtA and setup proofs. The output is zk.tex.

  ```bash
  bash scripts/run_artifact.sh times zk
  ```

- **Table 5:** both parts come from the multiparty benchmark, so one timing run covers them. Part (a) is one-time setup and per-party DKG time at t=n, with CGGMP20 auxiliary setup reported separately inside the DKG cell, written to dkg.tex. Part (b) is per-party offline/online signing time and communication at n=20 and t=2,3,7,11,20, written to sign.tex. WMY23 in the code corresponds to WMYC23 in the paper.

  ```bash
  bash scripts/run_artifact.sh times multiparty
  ```

- **Table 6:** two-party key generation and signing at t=n=2, reported separately for P1 and P2. The output is twoparty.tex.

  ```bash
  bash scripts/run_artifact.sh times twoparty
  ```

## Generate tables

The Python generators read existing measurements and emit LaTeX rows without rerunning experiments. Generate all five outputs through the runner:

```bash
bash scripts/run_artifact.sh tables all
```

Alternatively, run the generators directly from the repository root:

```bash
mkdir -p "$RESULTS_DIR/tables"
python3 scripts/build_mta_table.py      > "$RESULTS_DIR/tables/mta.tex"
python3 scripts/build_zk_table.py       > "$RESULTS_DIR/tables/zk.tex"
python3 scripts/build_dkg_table.py      > "$RESULTS_DIR/tables/dkg.tex"
python3 scripts/build_sign_table.py     > "$RESULTS_DIR/tables/sign.tex"
python3 scripts/build_twoparty_table.py > "$RESULTS_DIR/tables/twoparty.tex"
```

```text
target/
|-- criterion/     timing estimates (JSON)
|-- zk_sizes/      serialized proof sizes (TSV)
`-- comm_online/   communication measurements (TSV)

$RESULTS_DIR/
|-- raw/           zk_once.txt, protocol_once.txt, benchmark logs
|-- run.log        commands, environment, failures, and elapsed times
`-- tables/        mta.tex, zk.tex, dkg.tex, sign.tex, twoparty.tex
```

DKG uses timing data, ZK adds proof sizes, signing and two-party tables add communication, and MtA uses all three sources. A missing measurement appears as `--`, which is also used for phases that do not apply.

Compare the numerical columns at matching parameters. Setup is in seconds, other times are in milliseconds, and sizes are in KB. Protocol timings measure active computation over an in-memory transport and exclude network transfer.

Expected paper trends include substantial Paillier proof costs in Tables 3–4, low DKLs23 DKG and signing times in Table 5, and unequal P1/P2 costs in Table 6. Timing values need not match across different hardware.

After the measurements, export the raw data alongside the logs and tables. In Docker, this archive is written to the mounted host directory:

```bash
tar -czf "$RESULTS_DIR/measurements.tar.gz" target/criterion target/zk_sizes target/comm_online
```

## License

All crates in the repository are licensed as `MIT OR Apache-2.0`.
