# tecdsa-lib

tecdsa-lib implements threshold ECDSA protocols in Rust, with examples for key generation and signing and benchmarks for computation and communication costs.

- **Multi-party:** GGN16, GG18, LN18, CGGMP20, DKLs23, XAL23, WMY23, TX25, JTX25, WMC24, and LLZ25.
- **Two-party:** Lin17, KGG24, XAL21, and ABC24.

## Layout

```text
tecdsa-lib/
|-- crates/
|   |-- core/        base types, curves, big integers
|   |-- primitives/  cryptographic primitives
|   |-- framework/   sessions, transport, tests, benchmarks
|   |-- protocols/   protocol implementations
|   `-- tecdsa/      public facade
|-- scripts/        experiment runners and table generators
|-- tests/vectors/  wire-format test vectors
|-- vendor/         patched dependencies
`-- Dockerfile      docker file
```

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

For a new application without a lockfile, reuse the tested dependency versions. Run from the application directory:

```bash
cp ../tecdsa-lib/Cargo.lock Cargo.lock
cargo build --release
```

Follow the [DKLs23 example](crates/protocols/tecdsa-dkls23/examples/dkls23_keygen_sign.rs) for key generation and signing. Paillier-based crates also require the [dependency patch](Cargo.toml#L142), with its path adjusted for your application.

### Wire format

[tecdsa-wire](crates/framework/tecdsa-wire/src/codec.rs) provides `encode` and `decode` for this version 1 envelope:

```text
"MPCE" | version (u32 LE) | header length (u32 BE) | header | payload
```

The [header](crates/framework/tecdsa-wire/src/envelope.rs) contains session and protocol IDs, round, sender, and recipient. Header and payload use bincode 2 with big-endian, fixed-width integers.

## Benchmarks

Run the benchmarks with the default settings:

```bash
bash scripts/run_artifact.sh sizes
bash scripts/run_artifact.sh times all
```

Build files and measurements default to target/, while each command saves logs and tables in a timestamped directory under results/.

To run only the multi-party benchmarks with one execution per phase:

```bash
TECDSA_BENCH_RUNS=1 bash scripts/run_artifact.sh times multiparty
```

Setup, MtA, and ZK benchmarks use Criterion sampling independently of this count.

For more benchmarks, see the available suites and parameters:

```bash
bash scripts/run_artifact.sh help
bash scripts/run_artifact.sh list
```

## Results

Generate LaTeX tables from the saved measurements. The runner prints the output directory:

```bash
bash scripts/run_artifact.sh tables all
```

Table generation only reads saved data and does not rerun benchmarks. To choose an output path directly:

```bash
mkdir -p results/tables
python3 scripts/build_zk_table.py > results/tables/zk.tex
```

Tables use preset configurations and show `--` for missing data. For custom configurations, use the raw measurements.

```text
target/
|-- criterion/     timing estimates (JSON)
|-- zk_sizes/      proof sizes (TSV)
`-- comm_online/   communication (TSV)

results/<timestamp>/
|-- raw/           command output
|-- run.log        commands, configuration, and elapsed times
`-- tables/        generated LaTeX tables
```

Check run.log in the corresponding results directory for failed steps or worker panics.

## License

All crates are licensed as `MIT OR Apache-2.0`.
