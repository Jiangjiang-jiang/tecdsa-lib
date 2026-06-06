// SPDX-License-Identifier: MIT OR Apache-2.0
//! Homomorphic operations on Joye-Libert ciphertexts.
//!
//! The JL scheme is additively homomorphic:
//! - `Enc(a) * Enc(b) mod N = Enc(a + b mod 2^k)`
//! - `Enc(a)^s mod N = Enc(a * s mod 2^k)`

use rug::Integer;
use tecdsa_bigint::{mul_mod, pow_mod};

use crate::{enc_dec::JlCiphertext, kgen::JlPublicKey};

/// Homomorphic addition: computes `Enc(a + b mod 2^k)` from `Enc(a)` and `Enc(b)`.
///
/// `HAdd(c1, c2) = c1 * c2 mod N`
#[must_use]
pub fn hadd(pk: &JlPublicKey, c1: &JlCiphertext, c2: &JlCiphertext) -> JlCiphertext {
    let c = mul_mod(&c1.c, &c2.c, &pk.n);
    JlCiphertext { c }
}

/// Homomorphic scalar multiplication: computes `Enc(a * s mod 2^k)` from `Enc(a)` and scalar `s`.
///
/// `HScMul(ct, s) = ct^s mod N`
#[must_use]
pub fn hscmul(pk: &JlPublicKey, ct: &JlCiphertext, scalar: &Integer) -> JlCiphertext {
    let c = pow_mod(&ct.c, scalar, &pk.n);
    JlCiphertext { c }
}
