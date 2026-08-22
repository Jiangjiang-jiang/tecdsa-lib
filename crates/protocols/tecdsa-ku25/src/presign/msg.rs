// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wire messages for KU25 batch presigning.
//!
//! All payloads are flat, fixed-width blobs (see [`crate::wire`]) so that the
//! per-message overhead stays independent of the batch size.

use serde::{Deserialize, Serialize};

/// Round 3 payload: the verification challenge, opened only once every additive
/// shift the adversary can mount has already been committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignRound3 {
    /// This party's degree-`t` share of `r`.
    pub r_share: Vec<u8>,
    /// This party's degree-`t` share of `beta`.
    pub beta_share: Vec<u8>,
}

/// Round 4 payload: the batch check and the openings that turn a verified
/// triple into a presignature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignRound4 {
    /// This party's degree-`t` share `T_j` of the batch check.
    pub t_share: Vec<u8>,
    /// `m` packed scalars `w_{i,j}` (degree-`t` shares of `a_i k_i`).
    pub w: Vec<u8>,
    /// `m` packed SEC1-compressed points `R_{i,j} = g^{k_{i,j}}`.
    pub big_r: Vec<u8>,
}

/// Presign wire message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ku25PresignMsg {
    /// Round 1 (broadcast): `F_wmult` #1 -- `2m` packed scalars `e_j[i]` for the
    /// pairs `(k_i, a_i)` followed by the pairs `(r, a_i)`.
    Round1(Vec<u8>),
    /// Round 2 (broadcast): `F_wmult` #2 -- `m` packed scalars.
    Round2(Vec<u8>),
    /// Round 3 (broadcast): the openings of `r` and `beta`.
    Round3(PresignRound3),
    /// Round 4 (broadcast): `T_j` together with the `w_{i,j}` and `R_{i,j}` openings.
    Round4(PresignRound4),
}
