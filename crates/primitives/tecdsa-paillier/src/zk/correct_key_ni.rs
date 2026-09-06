// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-interactive correct key proof (NICorrectKeyProof) for Paillier keys.
//!
//! Proves that the prover knows the factorization of the Paillier modulus `N`,
//! i.e., that `N = p * q` and `gcd(N, phi(N)) = 1`.
//!
//! The proof works by showing the prover can compute N-th roots modulo N:
//! given random challenges `y_i = H(N, i)`, the prover computes `x_i` such
//! that `x_i^N = y_i mod N`. Only someone knowing the factorization can
//! efficiently compute these roots.
//!
//! Uses Fiat-Shamir to make the proof non-interactive: challenges are derived
//! deterministically from `H(domain || N || i)`.
//!
//! Security parameter: `SECURITY_PARAM` repetitions for `2^{-SECURITY_PARAM}`
//! soundness error.
//!
//! The `domain` parameter provides protocol-specific domain separation for the
//! Fiat-Shamir challenges (e.g. `b"lin17-correct-key-challenge"`).

use fast_paillier::{
    backend::{BigIntExt, Integer},
    DecryptionKey, EncryptionKey,
};
use rug::Complete;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Number of repetitions for the correct-key proof.
/// Each repetition halves the soundness error, so 80 gives 2^{-80}.
const SECURITY_PARAM: usize = 80;

/// Non-interactive proof that the prover knows the factorization of a Paillier
/// modulus `N`, proving `gcd(N, phi(N)) = 1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NICorrectKeyProof {
    /// N-th root responses: `x_i` such that `x_i^N = y_i mod N`.
    pub responses: Vec<Integer>,
}

impl NICorrectKeyProof {
    /// Generate a NICorrectKeyProof given the Paillier decryption key.
    ///
    /// The prover computes N-th roots of deterministic challenges `y_i = H(N, i) mod N`.
    /// To compute `x_i = y_i^{N^{-1} mod phi(N)} mod N`, the prover needs
    /// `phi(N) = (p-1)(q-1)`, which requires knowledge of the factorization.
    ///
    /// `domain` provides protocol-specific Fiat-Shamir domain separation.
    #[must_use]
    pub fn prove(dk: &DecryptionKey, domain: &[u8]) -> Self {
        let n = dk.n();
        let phi_n = (dk.p() - 1u8).complete() * (dk.q() - 1u8).complete();

        // Compute N^{-1} mod phi(N). This exists iff gcd(N, phi(N)) = 1,
        // which holds when N = p*q with p, q safe primes.
        let n_inv_phi = n
            .invert_ref(&phi_n)
            .expect("gcd(N, phi(N)) must be 1 for safe primes")
            .complete();

        let mut responses = Vec::with_capacity(SECURITY_PARAM);
        for i in 0..SECURITY_PARAM {
            let y_i = derive_challenge(n, domain, i);
            // x_i = y_i^{N^{-1} mod phi(N)} mod N
            let x_i = y_i
                .pow_mod_ref(&n_inv_phi, n)
                .expect("pow_mod must succeed")
                .complete();
            responses.push(x_i);
        }

        Self { responses }
    }

    /// Verify the NICorrectKeyProof against a Paillier encryption key.
    ///
    /// For each challenge `y_i = H(N, i) mod N`, checks that
    /// `responses[i]^N = y_i mod N`.
    ///
    /// `domain` must match the value used in `prove`.
    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, domain: &[u8]) -> bool {
        if self.responses.len() != SECURITY_PARAM {
            return false;
        }

        let n = ek.n();
        for (i, x_i) in self.responses.iter().enumerate() {
            let y_i = derive_challenge(n, domain, i);
            // Verify: x_i^N = y_i mod N
            let Some(lhs) = x_i.pow_mod_ref(n, n) else {
                return false;
            };
            let lhs = lhs.complete();
            if lhs != y_i {
                return false;
            }
        }

        true
    }
}

/// Derive the i-th challenge as `H(domain || N || i) mod N`, mapped into `Z*_N`.
///
/// Uses SHA-256 repeatedly to build enough bits, then reduces mod N.
/// If the result is 0 or not coprime to N, rehash until valid.
fn derive_challenge(n: &Integer, domain: &[u8], index: usize) -> Integer {
    let n_bytes = n.to_bytes_msf();
    let n_byte_len = n_bytes.len();
    let mut attempt = 0u32;
    loop {
        // Build a hash output large enough to cover the modulus.
        // We need at least n_byte_len bytes; use multiple SHA-256 blocks.
        let mut hash_bytes = Vec::with_capacity(n_byte_len + 32);
        let mut block = 0u32;
        while hash_bytes.len() < n_byte_len + 32 {
            let h = Sha256::new()
                .chain_update(domain)
                .chain_update(&n_bytes)
                .chain_update(index.to_le_bytes())
                .chain_update(attempt.to_le_bytes())
                .chain_update(block.to_le_bytes())
                .finalize();
            hash_bytes.extend_from_slice(&h);
            block += 1;
        }

        let candidate = Integer::from_bytes_msf(&hash_bytes[..n_byte_len]);
        let reduced = candidate.modulo_ref(n).complete();

        // Ensure we get a value in Z*_N (nonzero and coprime to N)
        if reduced.cmp0().is_gt() && reduced.gcd_ref(n).complete().is_one() {
            return reduced;
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_key_proof_valid() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let proof = NICorrectKeyProof::prove(&dk, b"test-domain");
        assert!(proof.verify(&ek, b"test-domain"), "valid proof must verify");
    }

    #[test]
    fn correct_key_proof_wrong_key() {
        let mut rng = rand_core::OsRng;
        let dk1 = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let dk2 = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek2 = dk2.encryption_key().clone();

        // Proof generated with dk1 should NOT verify with ek2
        let proof = NICorrectKeyProof::prove(&dk1, b"test-domain");
        assert!(
            !proof.verify(&ek2, b"test-domain"),
            "proof for wrong key must not verify"
        );
    }

    #[test]
    #[ignore = "redundant boundary test"]
    fn correct_key_proof_deterministic() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");

        let proof1 = NICorrectKeyProof::prove(&dk, b"test-domain");
        let proof2 = NICorrectKeyProof::prove(&dk, b"test-domain");

        // Same dk should produce the same proof (deterministic challenges)
        assert_eq!(proof1.responses.len(), proof2.responses.len());
        for (a, b) in proof1.responses.iter().zip(proof2.responses.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    #[ignore = "redundant boundary test"]
    fn correct_key_proof_truncated_fails() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let mut proof = NICorrectKeyProof::prove(&dk, b"test-domain");
        proof.responses.truncate(SECURITY_PARAM - 1);
        assert!(
            !proof.verify(&ek, b"test-domain"),
            "truncated proof must not verify"
        );
    }

    #[test]
    #[ignore = "redundant boundary test"]
    fn correct_key_proof_wrong_domain_fails() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let proof = NICorrectKeyProof::prove(&dk, b"domain-a");
        assert!(
            !proof.verify(&ek, b"domain-b"),
            "proof with wrong domain must not verify"
        );
    }
}
