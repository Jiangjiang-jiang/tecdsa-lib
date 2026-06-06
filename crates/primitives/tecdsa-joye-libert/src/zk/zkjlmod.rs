// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proof of correct JL modulus structure (`Pi_JLMod`).
//!
//! Proves that the modulus `N = p*q` has the required structure for JL
//! encryption: `p = 2^k * p' + 1` and `q = 2*q' + 1`.
//!
//! This is a one-time setup proof. In the XAL23 protocol, each party
//! proves their JL modulus is well-formed during key generation.
//!
//! The proof bundles:
//! 1. `Pi_QR2k` — proves `h` is a `2^k`-th power residue mod N
//! 2. `Pi_QR2kDL` — proves `y = h^alpha mod N` (i.e., discrete log consistency)
//!
//! Together these ensure the public key `(N, y, h, k)` is correctly constructed.

use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    kgen::{JlPublicKey, JlSecretKey},
    zk::{zkqr2k::ZkQr2kProof, zkqr2kdl::ZkQr2kDlProof},
};

/// Proof that a JL modulus and public key have the correct structural properties.
///
/// Bundles the two setup proofs required for a valid JL commitment scheme:
/// 1. `h` is a `2^k`-th power residue (proof of QR_{2^k} membership)
/// 2. `y = h^alpha mod N` (proof of discrete log relationship)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlModProof {
    /// Proof that h is a 2^k-th power residue mod N
    pub proof_qr2k: ZkQr2kProof,
    /// Proof that y = h^alpha mod N
    pub proof_qr2kdl: ZkQr2kDlProof,
}

impl ZkJlModProof {
    /// Creates a modulus correctness proof.
    ///
    /// # Arguments
    ///
    /// * `pk` - JL public key
    /// * `sk` - JL secret key (provides alpha)
    /// * `x` - the QNR element x such that h = x^{2^k} and y = x^alpha
    pub fn prove(
        pk: &JlPublicKey,
        sk: &JlSecretKey,
        x: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let proof_qr2k = ZkQr2kProof::prove(&pk.n, pk.k, x, &pk.h, rng);
        let proof_qr2kdl = ZkQr2kDlProof::prove(&pk.n, pk.k, &sk.alpha, &pk.h, &pk.y, rng);

        Self {
            proof_qr2k,
            proof_qr2kdl,
        }
    }

    /// Verifies the modulus correctness proof.
    #[must_use]
    pub fn verify(&self) -> bool {
        self.proof_qr2k.verify() && self.proof_qr2kdl.verify()
    }

    /// Verifies the proof and checks that the embedded public values
    /// match the claimed JL public key.
    ///
    /// This is the method that should be used by verifiers who receive
    /// the proof alongside a JL public key: it ensures the proof was
    /// constructed for exactly that key and not a different one.
    #[must_use]
    pub fn verify_for_pk(&self, pk: &JlPublicKey) -> bool {
        // Check that the QR2k proof is about the same (N, k, h)
        if self.proof_qr2k.n != pk.n || self.proof_qr2k.k != pk.k || self.proof_qr2k.h != pk.h {
            return false;
        }
        // Check that the QR2kDL proof is about the same (N, k, h, y)
        if self.proof_qr2kdl.n != pk.n
            || self.proof_qr2kdl.k != pk.k
            || self.proof_qr2kdl.h != pk.h
            || self.proof_qr2kdl.y != pk.y
        {
            return false;
        }
        self.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkjlmod_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let proof = ZkJlModProof::prove(&pk, &sk, &x, &mut rng);
        assert!(proof.verify());
    }
}
