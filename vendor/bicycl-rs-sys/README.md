# bicycl-rs-sys

Low-level Rust FFI bindings for the [BICYCL] C API. Upstream C++ sources are
vendored and compiled automatically without a pre-installed BICYCL library.
For a safe Rust interface, use [`bicycl-rs`] instead.

## System Requirements

- **CMake** >= 3.16
- **GMP**: `libgmp-dev`, `gmp-devel`
- **OpenSSL**: `libssl-dev`, `openssl-devel`
- A C++11-capable compiler

## License

`GPL-3.0-or-later`.

[BICYCL]: https://Jiangjiang-jiang/bicycl
[`bicycl-rs`]: https://crates.io/crates/bicycl-rs
