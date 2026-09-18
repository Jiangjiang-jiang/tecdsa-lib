# tecdsa-lib

tecdsa-lib implements threshold ECDSA protocols in Rust, with examples for key generation and signing and benchmarks for computation and communication costs.

- **Multi-party:** GGN16, GG18, LN18, CGGMP20, DKLs23, XAL23, WMY23, TX25, JTX25, WMC24, and LLZ25.
- **Two-party:** Lin17, KGG24, XAL21, and ABC24.

## Usage

1. **Clone the repository**

   ```bash
   git clone https://github.com/Jiangjiang-jiang/tecdsa-lib.git
   cd tecdsa-lib
   ```

   Run the following commands from the repository root unless stated otherwise.

2. **Build**

   Choose either a native build on your machine or Docker.

   **Native build**

   Building from source requires Rust stable, a C/C++ compiler, Make, and m4 on Linux. GMP is compiled from bundled sources. Python 3 is used to generate benchmark tables and needs no extra packages.

   Install the dependencies on Debian or Ubuntu. Skip the Rust installation lines if Rust is already installed.

   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential m4 python3 curl git ca-certificates

   # Install Rust and make Cargo available.
   curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
   source "$HOME/.cargo/env"
   ```

   Build the workspace:

   ```bash
   cargo build --locked --release --workspace
   ```

   **Docker build**

   Docker provides an alternative build environment. The image `tecdsa-artifact` contains the source, dependencies, and compiled benchmarks. Build and start it on the host:

   ```bash
   docker build -t tecdsa-artifact .
   mkdir -p results
   docker run -it --name tecdsa-eval -v "$PWD/results:/artifact/results" tecdsa-artifact
   ```

   Continue in the repository root for a native build, or in /artifact inside the container for Docker. Both environments support the Cargo and script commands below. The Docker results directory is shared with the host.

   Each protocol has a crate named `tecdsa-*`, where `*` is the lowercase protocol name. For example, to build DKLs23 and its dependencies:

   ```bash
   cargo build --locked --release -p tecdsa-dkls23
   ```

3. **Configure a protocol**

   The [DKLs23 example](crates/protocols/tecdsa-dkls23/examples/dkls23_keygen_sign.rs) uses 2-of-3 signing on secp256k1. In the source, set the party count and threshold in `run_keygen(n, t)`, the signing parties in `signer_indices`, and the bytes to sign in `message`. Each signature requires fresh presignatures.

4. **Run the protocol**

   ```bash
   cargo run --locked --release -p tecdsa-dkls23 --example dkls23_keygen_sign
   ```

   The example prints the signature and confirms verification:

   ```text
   ECDSA signature verification: PASSED
   ```

   Run the corresponding integration test:

   ```bash
   cargo test --locked --release -p tecdsa-dkls23 --test integration test_dkls23_full_sign_2_of_3 -- --exact
   ```

### Using a protocol crate in an application

For a Rust application next to this checkout, add the protocol crate to Cargo.toml:

```toml
[dependencies]
tecdsa-dkls23 = { path = "../tecdsa-lib/crates/protocols/tecdsa-dkls23" }
```

For a new application without a lockfile, start with the recorded dependency versions to keep the elliptic-curve prereleases compatible. Run these commands from the application directory:

```bash
cp ../tecdsa-lib/Cargo.lock Cargo.lock
cargo build --release
```

Follow the example through `Dkls23KeygenMachine`, `Dkls23PresignMachine`, and `Dkls23OnlineSignMachine`. Each implements [StateMachine](crates/framework/tecdsa-protocol/src/state_machine.rs) for sending and receiving protocol messages. The example handles message delivery locally through `Orchestrator`.

Other protocol crates and their tests are under [crates/protocols](crates/protocols). Constructors and supported parameters differ by protocol. When using Paillier-based crates in another project, also copy the [workspace dependency patch](Cargo.toml#L142) into the application manifest and adjust its path.

### Wire format

The example passes messages directly between parties in one process. For network communication, [tecdsa-session](crates/framework/tecdsa-session/src/lib.rs) encodes messages through [tecdsa-wire](crates/framework/tecdsa-wire/src/codec.rs), which provides `encode` and `decode`. The current envelope is version 1:

```text
"MPCE" | version (u32 LE) | header length (u32 BE) | header | payload
```

The [header](crates/framework/tecdsa-wire/src/envelope.rs) contains the session ID, protocol ID, round, sender, and recipient. Recipient 0xFFFF denotes broadcast. Header and payload use bincode 2 with big-endian, fixed-width integers, and the payload type depends on the protocol phase.

The transport must preserve message boundaries and provide authenticated, confidential delivery. Wire encoding itself supplies neither authentication nor encryption.

## Benchmarks

The benchmark runner measures proof sizes, communication, and execution time. Set the output directories and repetition count before running it:

```bash
# Save logs and tables in results/.
export RESULTS_DIR="$PWD/results"
# Keep build files and measurements in target/.
export CARGO_TARGET_DIR="$PWD/target"
# Execute each measured protocol phase ten times.
export TECDSA_BENCH_RUNS=10
export TECDSA_BENCH_JOBS=1

bash scripts/run_artifact.sh sizes
bash scripts/run_artifact.sh times all
```

The sizes command collects proof sizes and communication once. The times command runs the timing benchmarks. Select `zk`, `mta`, `multiparty`, or `twoparty` in place of `all` to run one suite. For example, run the multi-party suite with one execution per protocol phase:

```bash
TECDSA_BENCH_RUNS=1 bash scripts/run_artifact.sh times multiparty
```

Setup, MtA, and ZK benchmarks use Criterion sampling independently of this count. To measure only DKLs23 once with n=3 and t=2:

```bash
TECDSA_BENCH_PROTOCOLS=dkls23 \
TECDSA_BENCH_DKG_CONFIGS=3:2 \
TECDSA_BENCH_SIGN_N=3 \
TECDSA_BENCH_SIGN_THRESHOLDS=2 \
cargo run --locked --release -p tecdsa-bench --bin protocol_once
```

DKG configurations use comma-separated n:t pairs. Signing uses one total party count and a list of thresholds, each at most n. The protocol filter applies to the one-shot binary and the sizes command. It does not filter Criterion suites or change the example configuration.

See the runner help for all options and data sources:

```bash
bash scripts/run_artifact.sh help
bash scripts/run_artifact.sh list
```

## Results

Generate LaTeX tables from the saved measurements:

```bash
bash scripts/run_artifact.sh tables all
```

This writes mta.tex, zk.tex, dkg.tex, sign.tex, and twoparty.tex under results/tables. Select a suite in place of `all` to generate only its tables. The Python scripts can also be run directly, for example:

```bash
python3 scripts/build_zk_table.py > results/tables/zk.tex
```

Table generation reads existing data and does not rerun benchmarks. The generators use fixed parameter grids, so custom configurations should be read from the raw measurements. Missing measurements appear as `--`.

```text
target/
|-- criterion/     timing estimates (JSON)
|-- zk_sizes/      proof sizes (TSV)
`-- comm_online/   communication (TSV)

results/
|-- raw/           command output
|-- run.log        commands, configuration, and elapsed times
`-- tables/        generated LaTeX tables
```

The one-shot binary prints timings to the terminal and writes communication data under target/comm_online. The runner also saves command output and logs. Check these logs for failures, as a worker panic may not produce a nonzero exit code.

## License

All crates are licensed as `MIT OR Apache-2.0`.
