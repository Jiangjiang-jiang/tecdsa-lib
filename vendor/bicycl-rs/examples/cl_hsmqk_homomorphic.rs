//! Demonstrates the additive homomorphic property of CL_HSMqk encryption.
//!
//! CL_HSMqk is a class-group-based cryptosystem whose ciphertexts support
//! three operations *without decrypting*:
//!
//! - **Add two ciphertexts**: `Enc(a) ⊕ Enc(b) = Enc((a + b) mod q^k)`
//! - **Scalar multiplication**: `Enc(a) * s = Enc((a · s) mod q^k)`
//! - **Combined addscal**: `Enc(a) ⊕ Enc(b)*s = Enc((a + b·s) mod q^k)`
//!
//! These operations are the core building block for many MPC and ZK protocols.
//!
//! Parameters used here are intentionally small for a quick demonstration.
//! Production deployments should use security-level-derived parameters.
//!
//! Run with:
//! ```bash
//! cargo run -p bicycl-rs --example cl_hsmqk_homomorphic
//! ```
use bicycl_rs::Context;

fn main() -> Result<(), bicycl_rs::Error> {
    let ctx = Context::new()?;
    let mut rng = ctx.randgen_from_seed_decimal("1337")?;

    // CL_HSMqk parameters:
    //   q = 19   (prime; message exponent base)
    //   k = 2    (plaintext space is Z/q^k = Z/361)
    //   p = 193  (auxiliary class-group prime; must satisfy:
    //               - Kronecker(q,p) = -1
    //               - -q*p ≡ 1 mod 4
    //               - p > 4*q so the QFI representative is in reduced form)
    let q = "19";
    let k = 2u32;
    let p = "193";
    let modulus: i64 = 361; // q^k = 19^2

    let cl = ctx.cl_hsmqk(q, k, p)?;
    let (sk, pk) = cl.keygen(&ctx, &mut rng)?;
    println!("CL_HSMqk  q={q}  k={k}  plaintext space = Z/{modulus}");

    // ── Homomorphic addition ──────────────────────────────────────────────────
    let a: i64 = 123;
    let b: i64 = 250;
    let ct_a = cl.encrypt_decimal(&ctx, &pk, &mut rng, &a.to_string())?;
    let ct_b = cl.encrypt_decimal(&ctx, &pk, &mut rng, &b.to_string())?;

    let ct_sum = cl.add_ciphertexts(&ctx, &pk, &mut rng, &ct_a, &ct_b)?;
    let sum = cl.decrypt_decimal(&ctx, &sk, &ct_sum)?;
    let expected_sum = (a + b).rem_euclid(modulus).to_string();
    println!("Enc({a}) ⊕ Enc({b})      → {sum}  (expected {expected_sum})");
    assert_eq!(sum, expected_sum);

    // ── Scalar multiplication ─────────────────────────────────────────────────
    let s: i64 = 3;
    let ct_scaled = cl.scal_ciphertext_decimal(&ctx, &pk, &mut rng, &ct_a, &s.to_string())?;
    let scaled = cl.decrypt_decimal(&ctx, &sk, &ct_scaled)?;
    let expected_scaled = (a * s).rem_euclid(modulus).to_string();
    println!("Enc({a}) * {s}           → {scaled}  (expected {expected_scaled})");
    assert_eq!(scaled, expected_scaled);

    // ── Combined: a + b*s ────────────────────────────────────────────────────
    let ct_addscal =
        cl.addscal_ciphertexts_decimal(&ctx, &pk, &mut rng, &ct_a, &ct_b, &s.to_string())?;
    let addscal = cl.decrypt_decimal(&ctx, &sk, &ct_addscal)?;
    let expected_addscal = (a + b * s).rem_euclid(modulus).to_string();
    println!("Enc({a}) ⊕ Enc({b})*{s}  → {addscal}  (expected {expected_addscal})");
    assert_eq!(addscal, expected_addscal);

    println!("All homomorphic checks passed.");
    Ok(())
}
