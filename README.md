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

## Benchmarks and Results

The shell script `scripts/run_artifact.sh` is responsible for executing benchmarks and rendering results.

To reproduce the paper's results with the default settings, you need to:
1. Get the proof and communication size of every protocol:
   ```bash
   bash scripts/run_artifact.sh sizes
   ```
2. Measure the time of every protocol:
   ```bash
   bash scripts/run_artifact.sh times all
   ```

   This is equivalent to:

   ```bash
   bash scripts/run_artifact.sh times zk
   bash scripts/run_artifact.sh times mta
   bash scripts/run_artifact.sh times multiparty
   bash scripts/run_artifact.sh times twoparty
   ```

   Note that all benchmarks are executed multiple times to minimize the measurement errors. Among them, multi-party benchmarks are the most expensive, so we provide a flag `TECDSA_BENCH_RUNS` to control the number of executions. By setting it to a small value like `1`, multi-party benchmarks can complete faster with less measurement accuracy:

   ```bash
   TECDSA_BENCH_RUNS=1 bash scripts/run_artifact.sh times multiparty
   ```
   
   On the other hand, Setup, MtA, and ZK benchmarks are reasonably fast. For this reason, we directly use Criterion sampling for them, which cannot be controlled by `TECDSA_BENCH_RUNS`.

3. Generate LaTeX tables from the saved measurements:
   ```bash
   bash scripts/run_artifact.sh tables all
   ```

   This is equivalent to:

   ```bash
   bash scripts/run_artifact.sh tables zk
   bash scripts/run_artifact.sh tables mta
   bash scripts/run_artifact.sh tables multiparty
   bash scripts/run_artifact.sh tables twoparty
   ```

   The LaTeX code for the paper's Tables 3-6 should be printed to stdout (as well as in `results/<timestamp of the run>/tables/` by default). Timing values may not match across different hardware, but the trends should be similar to those reported in the submitted version. Sizes should match or differ slightly from the reported values (due to the serialization of random values).

---

To customize the settings or run benchmarks with finer granularity, see the available suites and parameters:

```bash
bash scripts/run_artifact.sh help
bash scripts/run_artifact.sh list
```

## License

All crates are licensed as `MIT OR Apache-2.0`.
