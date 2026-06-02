// SPDX-License-Identifier: MIT OR Apache-2.0
//! Re-exports of upstream [`paillier_zk`] (LFDT-Lockness) CGGMP20/24 ZK proofs.
//!
//! | Module | Paper name | Description |
//! |--------|-----------|-------------|
//! | [`paillier_encryption_in_range`] | `Pi_enc` | Plaintext is at most `l` bits |
//! | [`paillier_affine_operation_in_range`] | `Pi_aff_g` | Affine operation with group commitment |
//! | [`paillier_blum_modulus`] | `Pi_mod` | `N` is a Paillier-Blum modulus |
//! | [`no_small_factor`] | `Pi_fac` | Both factors of `N` are large |
//! | [`dlog_with_el_gamal_commitment`] | `Pi_elog` | Discrete-log with El-Gamal commitment |
//! | [`paillier_encryption_in_range_with_el_gamal`] | `Pi_enc_elg` | Enc-in-range with El-Gamal |

pub use paillier_zk::dlog_with_el_gamal_commitment;
pub use paillier_zk::no_small_factor;
pub use paillier_zk::paillier_affine_operation_in_range;
pub use paillier_zk::paillier_blum_modulus;
pub use paillier_zk::paillier_encryption_in_range;
pub use paillier_zk::paillier_encryption_in_range_with_el_gamal;

pub use paillier_zk::backend;
pub use paillier_zk::{BadExponent, IntegerExt, InvalidProof, PaillierError};
