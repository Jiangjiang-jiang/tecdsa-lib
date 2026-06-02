// SPDX-License-Identifier: MIT OR Apache-2.0
//! Zero-knowledge proofs for the Joye-Libert encryption scheme.
//!
//! All nine proof modules are fully implemented with `prove` and `verify`:
//!
//! - [`zkjl_enc`]: Encryption-in-range proof (R_JL_Enc)
//! - [`zkjl_aff`]: Affine operation proof (R_JL_Aff)
//! - [`zkjl_com`]: Commitment knowledge proof (R_JL_Com)
//! - [`zkjl_equ`]: Equality proof (R_JL_Equ)
//! - [`zkjlmod`]: Modular reduction proof (R_JLmod)
//! - [`zkjlv_com`]: Vector commitment knowledge proof (R_JLv_Com)
//! - [`zkjlv_equ`]: Vector equality proof (R_JLv_Equ)
//! - [`zkqr2k`]: Quadratic residue 2k proof (R_QR2k)
//! - [`zkqr2kdl`]: Quadratic residue 2k with discrete log (R_QR2kDL)

pub mod zkjl_aff;
pub mod zkjl_com;
pub mod zkjl_enc;
pub mod zkjl_equ;
pub mod zkjlmod;
pub mod zkjlv_com;
pub mod zkjlv_equ;
pub mod zkqr2k;
pub mod zkqr2kdl;
