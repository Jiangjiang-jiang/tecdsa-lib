// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proofs over Paillier ciphertexts.
//!
//! The `pi_*` modules are the CGGMP20/24 proofs; the rest are the GG18/Lin17-era
//! proofs this workspace uses directly.
//!
//! | Module | Paper name | Statement |
//! |---|---|---|
//! | [`pi_enc`] | `Пenc` | plaintext is at most `l` bits |
//! | [`pi_aff_g`] | `Пaff-g` | affine operation, with a group commitment |
//! | [`pi_mod`] | `Пmod` | `N` is a Paillier-Blum modulus |
//! | [`pi_fac`] | `Пfac` | both factors of `N` are large |
//! | [`pi_elog`] | `Пelog` | discrete log, with an El-Gamal commitment |
//! | [`pi_enc_elg`] | `Пenc-elg` | encryption in range, with an El-Gamal commitment |

use rug::{Complete, Integer};
use tecdsa_bigint::BigIntExt;
use thiserror::Error;

mod common;

pub mod pi_aff_g;
pub mod pi_elog;
pub mod pi_enc;
pub mod pi_enc_elg;
pub mod pi_fac;
pub mod pi_mod;

pub mod bridge;
pub mod correct_key_ni;
pub mod homo_elgamal;
pub mod homo_mult;
pub mod mta_range;
pub mod nonce_consist;
pub mod pdl;
pub mod pdl_slack;
pub mod pi_eq;
pub mod pia_pib;
pub mod range_ni;

use common::InvalidProofReason;
pub use common::{BadExponent, InvalidProof, PaillierError};

/// Error raised while constructing a proof.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(#[from] ErrorReason);

#[derive(Debug, Error)]
enum ErrorReason {
    #[error("couldn't evaluate modpow")]
    ModPow(
        #[source]
        #[from]
        BadExponent,
    ),
    #[error("couldn't find residue")]
    FindResidue,
    #[error("couldn't encrypt a message")]
    Encryption,
    #[error("can't find multiplicative inverse")]
    Invert,
    #[error("paillier error")]
    Paillier(#[source] crate::scheme::Error),
    #[error("bug: vec has unexpected length")]
    Length,
}

impl From<BadExponent> for Error {
    fn from(err: BadExponent) -> Self {
        Error(ErrorReason::ModPow(err))
    }
}

impl From<PaillierError> for Error {
    fn from(_err: PaillierError) -> Self {
        Error(ErrorReason::Encryption)
    }
}

impl From<crate::scheme::Error> for Error {
    fn from(err: crate::scheme::Error) -> Self {
        Self(ErrorReason::Paillier(err))
    }
}

/// Raw Paillier encryption `(1 + x*N) * r^N mod N^2`, with no range check on `x`.
///
/// [`crate::scheme::EncryptionKey::encrypt_with`] enforces `x` in
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
