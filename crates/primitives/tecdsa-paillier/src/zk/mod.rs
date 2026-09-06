// SPDX-License-Identifier: MIT OR Apache-2.0
use fast_paillier::backend::{BigIntExt, Integer};
use rug::Complete;

pub mod bridge;
pub mod correct_key_ni;
pub mod homo_elgamal;
pub mod homo_mult;
pub mod mta_range;
pub mod nonce_consist;
pub mod paillier_zk;
pub mod pdl;
pub mod pdl_slack;
pub mod pi_eq;
pub mod pia_pib;
pub mod range_ni;

/// Raw Paillier encryption `(1 + x*N) * r^N mod N^2`, with no range check on `x`.
///
/// [`fast_paillier::EncryptionKey::encrypt_with`] enforces `x` in
/// `{-N/2, ..., N/2}`, but ZK responses routinely exceed that range, so the
/// proofs need this unchecked form. Uses the binomial identity
/// `(1 + N)^x = 1 + x*N (mod N^2)` to avoid a modular exponentiation.
///
/// `nn` must equal `n * n`; it is passed in because callers already have it.
///
/// # Panics
/// Panics if `r` is not invertible modulo `nn`.
pub(crate) fn paillier_encrypt_raw(n: &Integer, nn: &Integer, x: &Integer, r: &Integer) -> Integer {
    let one_plus_xn = (Integer::one() + x * n).modulo(nn);
    let r_to_n = r
        .pow_mod_ref(n, nn)
        .expect("nonce is invertible modulo n^2")
        .complete();
    (one_plus_xn * r_to_n).modulo(nn)
}
