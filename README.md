# tecdsa-lib

A Rust library for threshold ECDSA and two-party ECDSA.

## Protocols

The workspace currently includes these protocol crates:

- **Multi-party Threshold Protocols**: GGN16, GG18, LN18, CGGMP20, DKLs23, XAL23, WMY23, TX25, JTX25, WMC24, LLZ25, DNP25(Trout), KU25
- **Two-Party Protocols**: Lin17, KGG24, XAL21, ABC24

## Layout

```text
tecdsa-lib/
├── core/          base types, curve interfaces, bigint wrappers
├── primitives/    reusable cryptographic primitives
├── framework/     protocol framework, wire, session, transport, testkit
├── protocols/     protocol implementations
└── tecdsa/        public facade crate

tests/             integration tests
benchmark/         benchmark-related files
vendor/            local patches and vendored dependencies
```

## Build

Build the full workspace:

```bash
cargo build --workspace --all-features
```

Run tests:

```bash
cargo test --workspace --all-features
```

## License

All crates in the repository are licensed as `MIT OR Apache-2.0`.
