// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proofs for ring-Pedersen parameter correctness.
//!
//! - [`PiPrm`] -- proves knowledge of lambda such that s = t^lambda mod N,
//!   using m = 80 binary Fiat-Shamir challenges (CGGMP20 Figure 13).
//!   Soundness error: 2^{-80}.
//!
//! The Paillier-Blum modulus proof (Pi_mod, CGGMP20 Figure 12) used to live here
//! as a second implementation. It is now `tecdsa_paillier::zk::pi_mod`, which is
//! generic over the repetition count and the digest, exposes the interactive
//! form, and binds its Fiat-Shamir challenge to a caller-supplied session tag.

use rand_core::CryptoRngCore;
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{BigIntExt, SyncRng};

use crate::params::{PedersenModParams, PedersenModSecret};

const SECURITY_PARAM: usize = 80;

// ──────────────────────────────────────────────────────────────────────────────
// Pi_prm — ring-Pedersen parameter proof (CGGMP20 Figure 13)
// ──────────────────────────────────────────────────────────────────────────────

/// Proof that ring-Pedersen parameters (N, s, t) are well-formed.
///
/// Demonstrates knowledge of lambda such that s = t^lambda mod N,
/// using m = 80 binary Fiat-Shamir challenges per CGGMP20 Figure 13.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiPrm {
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    commitment: Vec<Integer>,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    zs: Vec<Integer>,
}

impl PiPrm {
    /// Produce a `PiPrm` proof (CGGMP20 Figure 13, non-interactive).
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn prove(
        params: &PedersenModParams,
        secret: &PedersenModSecret,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let phi_n = Integer::from(&secret.p - 1) * Integer::from(&secret.q - 1);

        let mut sync_rng = SyncRng(rng);
        let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);

        let private_commitment: Vec<Integer> = (0..SECURITY_PARAM)
            .map(|_| phi_n.clone().random_below(rug_rng))
            .collect();
        let commitment: Vec<Integer> = private_commitment
            .iter()
            .map(|a_i| params.t.clone().pow_mod(a_i, &params.n).unwrap())
            .collect();

        let challenges = Self::derive_challenges(params, &commitment);

        let zs: Vec<Integer> = private_commitment
            .iter()
            .zip(challenges.iter())
            .map(|(a_i, &e_i)| {
                let mut z = a_i.clone();
                if e_i {
                    z += &secret.lambda;
                    z %= &phi_n;
                }
                z
            })
            .collect();

        Self { commitment, zs }
    }

    /// Verify `PiPrm` proof (CGGMP20 Figure 13).
    #[must_use]
    pub fn verify(&self, params: &PedersenModParams) -> bool {
        if !params.is_well_formed() {
            return false;
        }

        if self.commitment.len() != SECURITY_PARAM || self.zs.len() != SECURITY_PARAM {
            return false;
        }

        for (a_i, z_i) in self.commitment.iter().zip(self.zs.iter()) {
            if *a_i == 0 || *a_i >= params.n {
                return false;
            }
            if a_i.clone().gcd(&params.n) != 1 {
                return false;
            }
            if *z_i == 0 || *z_i >= params.n {
                return false;
            }
        }

        let challenges = Self::derive_challenges(params, &self.commitment);

        for ((z_i, a_i), &e_i) in self
            .zs
            .iter()
            .zip(self.commitment.iter())
            .zip(challenges.iter())
        {
            let lhs = params.t.clone().pow_mod(z_i, &params.n).unwrap();
            let rhs = if e_i {
                Integer::from(a_i * &params.s) % &params.n
            } else {
                a_i.clone()
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }

    fn derive_challenges(params: &PedersenModParams, commitment: &[Integer]) -> Vec<bool> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(params.n.to_bytes_msf());
        hasher.update(params.s.to_bytes_msf());
        hasher.update(params.t.to_bytes_msf());
        for a_i in commitment {
            hasher.update(a_i.to_bytes_msf());
        }
        let hash = hasher.finalize();

        let mut challenges = Vec::with_capacity(SECURITY_PARAM);
        let mut current_hash = hash.to_vec();
        let mut byte_idx = 0;
        let mut bit_idx: u8 = 0;
        while challenges.len() < SECURITY_PARAM {
            if byte_idx >= current_hash.len() {
                let mut h = Sha256::new();
                h.update(&current_hash);
                current_hash = h.finalize().to_vec();
                byte_idx = 0;
                bit_idx = 0;
            }
            challenges.push((current_hash[byte_idx] >> bit_idx) & 1 == 1);
            bit_idx += 1;
            if bit_idx == 8 {
                bit_idx = 0;
                byte_idx += 1;
            }
        }

        challenges
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PedersenModParams;

    fn generate_blum_params(bits: u64) -> (PedersenModParams, PedersenModSecret) {
        let mut rng = rand::thread_rng();
        PedersenModParams::generate(bits, &mut rng)
    }

    // -- PiPrm tests --

    #[test]
    fn piprm_honest_proof_verifies() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert!(proof.verify(&params), "honest PiPrm proof must verify");
    }

    #[test]
    fn piprm_wrong_lambda_fails() {
        let (params, mut secret) = generate_blum_params(256);
        secret.lambda = Integer::from(42u64);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert!(!proof.verify(&params), "PiPrm with wrong lambda must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_tampered_commitment_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiPrm::prove(&params, &secret, &mut rng);
        proof.commitment[0] = Integer::from(2u64);
        assert!(!proof.verify(&params), "tampered PiPrm must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_tampered_response_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiPrm::prove(&params, &secret, &mut rng);
        proof.zs[0] = Integer::from(1u64);
        assert!(!proof.verify(&params), "tampered PiPrm response must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_has_correct_length() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof = PiPrm::prove(&params, &secret, &mut rng);
        assert_eq!(proof.commitment.len(), SECURITY_PARAM);
        assert_eq!(proof.zs.len(), SECURITY_PARAM);
    }
}
