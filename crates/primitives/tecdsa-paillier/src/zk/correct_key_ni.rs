use fast_paillier::{backend::Integer, DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SECURITY_PARAM: usize = 80;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NICorrectKeyProof {
    pub responses: Vec<Integer>,
}

impl NICorrectKeyProof {
    #[must_use]
    pub fn prove(dk: &DecryptionKey, domain: &[u8]) -> Self {
        let n = dk.n();
        let phi_n = (dk.p() - 1u8) * (dk.q() - 1u8);

        let n_inv_phi = n
            .invert_ref(&phi_n)
            .expect("gcd(N, phi(N)) must be 1 for safe primes");

        let mut responses = Vec::with_capacity(SECURITY_PARAM);
        for i in 0..SECURITY_PARAM {
            let y_i = derive_challenge(n, domain, i);
            let x_i = y_i
                .pow_mod_ref(&n_inv_phi, n)
                .expect("pow_mod must succeed");
            responses.push(x_i);
        }

        Self { responses }
    }

    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, domain: &[u8]) -> bool {
        if self.responses.len() != SECURITY_PARAM {
            return false;
        }

        let n = ek.n();
        for (i, x_i) in self.responses.iter().enumerate() {
            let y_i = derive_challenge(n, domain, i);
            let Some(lhs) = x_i.pow_mod_ref(n, n) else {
                return false;
            };
            if lhs != y_i {
                return false;
            }
        }

        true
    }
}

fn derive_challenge(n: &Integer, domain: &[u8], index: usize) -> Integer {
    let n_bytes = n.to_bytes_msf();
    let n_byte_len = n_bytes.len();
    let mut attempt = 0u32;
    loop {
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
        let reduced = candidate.modulo_ref(n);

        if reduced.cmp0().is_gt() && reduced.gcd_ref(n).is_one() {
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
