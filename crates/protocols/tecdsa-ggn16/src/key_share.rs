// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    threshold::{DecryptionShare, ThresholdSetup},
};
use zeroize::Zeroize;

/// A single party's key share produced by GGN16 key generation.
///
/// Contains the party's secret additive share $x_i$, the joint public key
/// $y = g^x$, the global ciphertext $\alpha = E(x)$ under the shared
/// Paillier key, and the threshold decryption share.
#[derive(Clone)]
pub struct Ggn16KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's index (1-based).
    pub party_index: u16,
    /// Secret additive share $x_i$ of the ECDSA signing key.
    pub secret_share: C::Scalar,
    /// Joint ECDSA public key $y = g^x$.
    pub public_key: C::ProjectivePoint,
    /// Public verification shares $y_j = g^{x_j}$ for all parties.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// Global ciphertext $\alpha = E(x)$ under the shared Paillier key.
    pub alpha: Integer,
    /// Threshold Paillier setup (shared public parameters).
    pub threshold_setup: ThresholdSetup,
    /// This party's threshold Paillier decryption share.
    pub decryption_share: DecryptionShare,
    /// Ring-Pedersen auxiliary parameters $(\tilde{N}, h_1, h_2)$ for ZK proofs.
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
    /// Threshold $t$: at least $t+1$ parties needed.
    pub threshold: u16,
    /// Total parties $n$.
    pub total: u16,
}

impl<C: TecdsaCurve> Zeroize for Ggn16KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.decryption_share.zeroize();
    }
}
