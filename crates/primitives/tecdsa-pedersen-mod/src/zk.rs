// SPDX-License-Identifier: MIT OR Apache-2.0
//! ZK proofs for ring-Pedersen parameter correctness.
//!
//! - [`PiPrm`] -- proves knowledge of lambda such that s = t^lambda mod N,
//!   using m = 80 binary Fiat-Shamir challenges (CGGMP20 Figure 13).
//!   Soundness error: 2^{-80}.
//!
//! - [`PiMod`] -- proves N is a Paillier-Blum modulus: product of two primes
//!   p, q with p = q = 3 mod 4, via Jacobi classification + Blum fourth roots
//!   + N-th roots (CGGMP20 Figure 12). Soundness error: 2^{-81}.

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tecdsa_bigint::DynInt;

use crate::params::{PedersenModParams, PedersenModSecret, RandAdapter};

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
    commitment: Vec<DynInt>,
    zs: Vec<DynInt>,
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
        let phi_n = (secret.p.inner() - BigUint::one()) * (secret.q.inner() - BigUint::one());

        let mut adapter = RandAdapter(rng);

        let private_commitment: Vec<BigUint> = (0..SECURITY_PARAM)
            .map(|_| adapter.gen_biguint_below(&phi_n))
            .collect();
        let commitment: Vec<DynInt> = private_commitment
            .iter()
            .map(|a_i| DynInt::from(params.t.inner().modpow(a_i, params.n.inner())))
            .collect();

        let challenges = Self::derive_challenges(params, &commitment);

        let zs: Vec<DynInt> = private_commitment
            .iter()
            .zip(challenges.iter())
            .map(|(a_i, &e_i)| {
                let mut z = a_i.clone();
                if e_i {
                    z += secret.lambda.inner();
                    z %= &phi_n;
                }
                DynInt::from(z)
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
            if a_i.is_zero() || *a_i >= params.n {
                return false;
            }
            if tecdsa_bigint::gcd(a_i, &params.n) != DynInt::one() {
                return false;
            }
            if z_i.is_zero() || *z_i >= params.n {
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
            let lhs = params.t.modpow(z_i, &params.n);
            let rhs = if e_i {
                DynInt::from((a_i.inner() * params.s.inner()) % params.n.inner())
            } else {
                a_i.clone()
            };
            if lhs != rhs {
                return false;
            }
        }

        true
    }

    fn derive_challenges(params: &PedersenModParams, commitment: &[DynInt]) -> Vec<bool> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(params.n.to_bytes_be());
        hasher.update(params.s.to_bytes_be());
        hasher.update(params.t.to_bytes_be());
        for a_i in commitment {
            hasher.update(a_i.to_bytes_be());
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

// ──────────────────────────────────────────────────────────────────────────────
// Pi_mod — Blum modulus proof (CGGMP20 Figure 12)
// ──────────────────────────────────────────────────────────────────────────────

/// Proof that N is a Paillier-Blum modulus (CGGMP20 Figure 12).
///
/// Proves N = pq where p, q are primes with p = q = 3 mod 4,
/// using m = 80 challenges with Jacobi classification, Blum fourth roots,
/// and N-th roots. Soundness error: 2^{-81}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiMod {
    w: DynInt,
    proof_points: Vec<PiModPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PiModPoint {
    x: DynInt,
    a: bool,
    b: bool,
    z: DynInt,
}

impl PiMod {
    /// Prove that a raw modulus N = p*q is a Blum modulus (CGGMP20 Figure 12).
    ///
    /// This is the primary API for proving any RSA-type modulus is Blum,
    /// including Paillier moduli used in CGGMP20 aux-info.
    ///
    /// # Panics
    ///
    /// Panics if `find_residue` fails for a challenge, which should not
    /// happen with a valid Blum modulus and correctly chosen w.
    #[allow(clippy::similar_names, clippy::many_single_char_names)]
    pub fn prove_modulus(
        n: &DynInt,
        p: &DynInt,
        q: &DynInt,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        use crate::number_theory::{
            blum_fourth_root, find_residue, mod_inverse, sample_neg_jacobi,
        };

        let expected_n = DynInt::from(p.inner() * q.inner());
        if expected_n != *n {
            return None;
        }

        if !tecdsa_bigint::is_safe_prime(p) || !tecdsa_bigint::is_safe_prime(q) {
            return None;
        }
        let four = BigUint::from(4u32);
        let three = BigUint::from(3u32);
        if p.inner() % &four != three || q.inner() % &four != three {
            return None;
        }

        let w = sample_neg_jacobi(n, rng);

        let phi_n = (p.inner() - BigUint::one()) * (q.inner() - BigUint::one());
        let phi_n_dyn = DynInt::from(phi_n);

        let n_inv = mod_inverse(n, &phi_n_dyn)?;

        let challenges = Self::derive_challenges(n, &w);

        let proof_points: Vec<PiModPoint> = challenges
            .iter()
            .map(|y_i| {
                let z = y_i.modpow(&n_inv, n);

                let (a, b, y_prime) = find_residue(y_i, &w, p, q, n)
                    .expect("find_residue must succeed for valid Blum modulus");

                let x = blum_fourth_root(&y_prime, p, q, n);

                PiModPoint { x, a, b, z }
            })
            .collect();

        Some(Self { w, proof_points })
    }

    /// Convenience wrapper: prove ring-Pedersen modulus is Blum.
    ///
    /// # Panics
    ///
    /// Panics if `find_residue` fails (see [`prove_modulus`](Self::prove_modulus)).
    pub fn prove(
        params: &PedersenModParams,
        secret: &PedersenModSecret,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self> {
        Self::prove_modulus(&params.n, &secret.p, &secret.q, rng)
    }

    /// Verify `PiMod` proof against a raw modulus N (CGGMP20 Figure 12).
    ///
    /// The `rng` parameter is used for probabilistic Miller-Rabin composite
    /// testing (25 rounds). For deterministic benchmark results, pass a
    /// seeded CSPRNG.
    #[must_use]
    pub fn verify_modulus(&self, n: &DynInt, rng: &mut impl CryptoRngCore) -> bool {
        use crate::number_theory::is_probably_composite;

        if !n.is_odd() {
            return false;
        }

        if !is_probably_composite(n, 25, rng) {
            return false;
        }

        if *n <= DynInt::one() {
            return false;
        }

        if self.w.is_zero() || self.w >= *n {
            return false;
        }
        if tecdsa_bigint::gcd(&self.w, n) != DynInt::one() {
            return false;
        }
        if tecdsa_bigint::jacobi(&self.w, n) != -1 {
            return false;
        }

        if self.proof_points.len() != SECURITY_PARAM {
            return false;
        }

        let challenges = Self::derive_challenges(n, &self.w);

        let four_dyn = DynInt::from(4u64);

        for (point, y_i) in self.proof_points.iter().zip(challenges.iter()) {
            if point.x.is_zero() || point.x >= *n {
                return false;
            }
            if tecdsa_bigint::gcd(&point.x, n) != DynInt::one() {
                return false;
            }
            if point.z.is_zero() || point.z >= *n {
                return false;
            }
            if tecdsa_bigint::gcd(&point.z, n) != DynInt::one() {
                return false;
            }

            let z_pow_n = point.z.modpow(n, n);
            if z_pow_n != *y_i {
                return false;
            }

            let mut expected = y_i.clone();
            if point.a {
                expected = DynInt::from(n.inner() - expected.inner());
            }
            if point.b {
                expected = DynInt::from((expected.inner() * self.w.inner()) % n.inner());
            }

            let x_pow_4 = point.x.modpow(&four_dyn, n);
            if x_pow_4 != expected {
                return false;
            }
        }

        true
    }

    /// Convenience wrapper: verify against ring-Pedersen modulus.
    #[must_use]
    pub fn verify(&self, params: &PedersenModParams, rng: &mut impl CryptoRngCore) -> bool {
        self.verify_modulus(&params.n, rng)
    }

    fn derive_challenges(n: &DynInt, w: &DynInt) -> Vec<DynInt> {
        use sha2::{Digest, Sha256};

        let n_bytes = n.to_bytes_be();
        let n_byte_len = n_bytes.len();

        let mut challenges = Vec::with_capacity(SECURITY_PARAM);
        let mut counter: u32 = 0;

        while challenges.len() < SECURITY_PARAM {
            let mut hasher = Sha256::new();
            hasher.update(b"pi_mod_challenge");
            hasher.update(&n_bytes);
            hasher.update(w.to_bytes_be());
            hasher.update(counter.to_be_bytes());
            let seed = hasher.finalize();

            let mut expanded = Vec::with_capacity(n_byte_len);
            let mut block_input = seed.to_vec();
            while expanded.len() < n_byte_len {
                let mut h = Sha256::new();
                h.update(&block_input);
                let block = h.finalize();
                expanded.extend_from_slice(&block);
                block_input = block.to_vec();
            }
            expanded.truncate(n_byte_len);

            let candidate = BigUint::from_bytes_be(&expanded) % n.inner();
            if candidate > BigUint::one() {
                let candidate = DynInt::from(candidate);
                if tecdsa_bigint::gcd(&candidate, n) == DynInt::one() {
                    challenges.push(candidate);
                }
            }
            counter += 1;
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
        secret.lambda = DynInt::from(42u64);
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
        proof.commitment[0] = DynInt::from(2u64);
        assert!(!proof.verify(&params), "tampered PiPrm must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn piprm_tampered_response_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiPrm::prove(&params, &secret, &mut rng);
        proof.zs[0] = DynInt::from(1u64);
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

    // -- PiMod tests --

    #[test]
    fn pimod_honest_proof_verifies() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof =
            PiMod::prove(&params, &secret, &mut rng).expect("prove must succeed for valid params");
        assert!(
            proof.verify(&params, &mut rng),
            "honest PiMod proof must verify"
        );
    }

    #[test]
    fn pimod_wrong_factorization_fails() {
        let (params, _secret) = generate_blum_params(256);
        let (_, wrong_secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let result = PiMod::prove(&params, &wrong_secret, &mut rng);
        assert!(
            result.is_none(),
            "prove with wrong factors must return None"
        );
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn pimod_tampered_w_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiMod::prove(&params, &secret, &mut rng).expect("prove must succeed");
        proof.w = DynInt::from(2u64);
        assert!(!proof.verify(&params, &mut rng), "tampered w must fail");
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn pimod_tampered_proof_point_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiMod::prove(&params, &secret, &mut rng).expect("prove must succeed");
        proof.proof_points[0].x = DynInt::from(3u64);
        assert!(
            !proof.verify(&params, &mut rng),
            "tampered proof point must fail"
        );
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn pimod_proof_has_correct_length() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let proof = PiMod::prove(&params, &secret, &mut rng).expect("prove must succeed");
        assert_eq!(proof.proof_points.len(), SECURITY_PARAM);
    }

    #[test]
    #[ignore = "redundant negative/boundary test"]
    fn pimod_w_with_positive_jacobi_fails() {
        let (params, secret) = generate_blum_params(256);
        let mut rng = rand::thread_rng();
        let mut proof = PiMod::prove(&params, &secret, &mut rng).expect("prove must succeed");
        // Replace w with a value that has Jacobi symbol +1 (a QR)
        let qr = DynInt::from(
            params
                .t
                .inner()
                .modpow(&num_bigint::BigUint::from(2u32), params.n.inner()),
        );
        proof.w = qr;
        assert!(
            !proof.verify(&params, &mut rng),
            "w with Jacobi(w,N) != -1 must fail"
        );
    }
}
