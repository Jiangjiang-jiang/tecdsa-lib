# bicycl-rs

Safe Rust bindings for the [BICYCL](https://github.com/Jiangjiang-jiang/bicycl) cryptographic library. All wrapper types
are `!Send + !Sync` since the underlying C library is not thread-safe.

## Requirements

- **CMake** >= 3.16
- **GMP**: `libgmp-dev`, `gmp-devel`
- **OpenSSL**: `libssl-dev`, `openssl-devel`
- A C++11-capable compiler

## Usage

```toml
[dependencies]
bicycl-rs = "0.1"
```

```rust
use bicycl_rs::{Context, Error};

fn main() -> Result<(), Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("12345")?;

    // q: subgroup order (prime), k: plaintext-space exponent (Z/q^k), p: class-group prime
    let q = "1461501637330902918203684832716283019655932542983";
    let p = "730750818665451459101842416358141509827966271488";
    let cl = ctx.cl_hsmqk(q, 1, p)?;

    // Key generation
    let (sk, pk) = cl.keygen(&ctx, &mut rng)?;

    // Encrypt / decrypt
    let ct = cl.encrypt_decimal(&ctx, &pk, &mut rng, "42")?;
    let plain = cl.decrypt_decimal(&ctx, &sk, &ct)?;
    assert_eq!(plain, "42");

    // Homomorphic scalar multiplication: Enc(42) * 3 = Enc(126)
    let ct2 = cl.scal_ciphertext_decimal(&ctx, &pk, &mut rng, &ct, "3")?;
    assert_eq!(cl.decrypt_decimal(&ctx, &sk, &ct2)?, "126");

    // Low-level: access subgroup generator h and compute h^r
    let h = cl.h(&ctx)?;
    let hr = cl.power_of_h_decimal(&ctx, "7")?;
    assert!(h.equal(&ctx, &hr)? == false); // h != h^7 (unless r=1)

    // Low-level: decompose and reconstruct a ciphertext
    let c1 = ct.c1(&ctx)?;
    let c2 = ct.c2(&ctx)?;
    let ct_copy = bicycl_rs::ClHsmqkCiphertext::from_c1c2(&ctx, &c1, &c2)?;
    assert_eq!(cl.decrypt_decimal(&ctx, &sk, &ct_copy)?, "42");

    // Secret key round-trip through decimal
    let sk_dec = sk.to_decimal(&ctx)?;
    let sk2 = bicycl_rs::ClHsmqkSecretKey::from_decimal(&ctx, &cl, &sk_dec)?;
    assert_eq!(cl.decrypt_decimal(&ctx, &sk2, &ct)?, "42");

    Ok(())
}
```

## License

`GPL-3.0-or-later`.
