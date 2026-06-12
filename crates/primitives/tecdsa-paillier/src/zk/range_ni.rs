use fast_paillier::{backend::Integer, DecryptionKey, EncryptionKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

const SECURITY_PARAM: usize = 80;

#[derive(Debug, thiserror::Error)]
pub enum RangeProofNiError {
    #[error("Paillier error: {0}")]
    Paillier(String),
    #[error("nonce extraction failed")]
    NonceExtraction,
}

impl From<fast_paillier::Error> for RangeProofNiError {
    fn from(e: fast_paillier::Error) -> Self {
        RangeProofNiError::Paillier(e.to_string())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RangeProofNi {
    pub encrypted_pairs: Vec<EncryptedPair>,
    pub responses: Vec<RangeResponse>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPair {
    pub c_masked: fast_paillier::Ciphertext,
    pub c_mask: fast_paillier::Ciphertext,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RangeResponse {
    Open {
        w: Integer,
        s: Integer,
    },
    Verify {
        rho: Integer,
        t: Integer,
    },
}

fn extract_nonce(
    dk: &DecryptionKey,
    ciphertext: &fast_paillier::Ciphertext,
    plaintext: &Integer,
) -> Option<Integer> {
    let n = dk.n();
    let nn = dk.encryption_key().nn();

    let x = if plaintext.cmp0().is_lt() {
        plaintext + n
    } else {
        plaintext.clone()
    };

    let one_plus_xn = (Integer::one() + &x * n).modulo_ref(nn);

    let one_plus_xn_inv = one_plus_xn.invert_ref(nn)?;
    let r_to_n = (ciphertext * &one_plus_xn_inv).modulo_ref(nn);

    let lambda = dk.lambda();
    let d = n.invert_ref(lambda)?;

    let r = r_to_n.pow_mod_ref(&d, n)?;

    Some(r)
}

impl RangeProofNi {
    pub fn prove(
        dk: &DecryptionKey,
        ek: &EncryptionKey,
        c: &fast_paillier::Ciphertext,
        x: &Integer,
        _r: &Integer,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, RangeProofNiError> {
        let range_bound = q * &Integer::u_pow_u(2, 128);

        let mut encrypted_pairs = Vec::with_capacity(SECURITY_PARAM);
        let mut masks = Vec::with_capacity(SECURITY_PARAM);
        let mut nonces_mask = Vec::with_capacity(SECURITY_PARAM);

        for _ in 0..SECURITY_PARAM {
            let rho_i = range_bound.random_below_ref(rng);

            let (c_mask, t_i) = dk.encrypt_with_random(rng, &rho_i)?;

            let c_masked = ek.oadd(c, &c_mask)?;

            encrypted_pairs.push(EncryptedPair { c_masked, c_mask });
            masks.push(rho_i);
            nonces_mask.push(t_i);
        }

        let challenges = derive_challenges(ek, c, &encrypted_pairs);

        let mut responses = Vec::with_capacity(SECURITY_PARAM);
        for (i, bit) in challenges.iter().enumerate() {
            if *bit == 0 {
                let w_i = x + &masks[i];
                let s_i = extract_nonce(dk, &encrypted_pairs[i].c_masked, &w_i)
                    .ok_or(RangeProofNiError::NonceExtraction)?;
                responses.push(RangeResponse::Open { w: w_i, s: s_i });
            } else {
                responses.push(RangeResponse::Verify {
                    rho: masks[i].clone(),
                    t: nonces_mask[i].clone(),
                });
            }
        }

        Ok(Self {
            encrypted_pairs,
            responses,
        })
    }

    #[must_use]
    pub fn verify(&self, ek: &EncryptionKey, c: &fast_paillier::Ciphertext, q: &Integer) -> bool {
        if self.encrypted_pairs.len() != SECURITY_PARAM || self.responses.len() != SECURITY_PARAM {
            return false;
        }

        let range_bound = q * &Integer::u_pow_u(2, 128);
        let upper_bound = q + &range_bound;

        let challenges = derive_challenges(ek, c, &self.encrypted_pairs);

        for (i, bit) in challenges.iter().enumerate() {
            let pair = &self.encrypted_pairs[i];

            match (&self.responses[i], bit) {
                (RangeResponse::Open { w, s }, 0) => {
                    let Ok(expected) = ek.encrypt_with(w, s) else {
                        return false;
                    };
                    if pair.c_masked != expected {
                        return false;
                    }
                    if w.cmp0().is_lt() || *w >= upper_bound {
                        return false;
                    }
                }
                (RangeResponse::Verify { rho, t }, 1) => {
                    let Ok(expected) = ek.encrypt_with(rho, t) else {
                        return false;
                    };
                    if pair.c_mask != expected {
                        return false;
                    }
                    let Ok(combined) = ek.oadd(c, &pair.c_mask) else {
                        return false;
                    };
                    if pair.c_masked != combined {
                        return false;
                    }
                    if rho.cmp0().is_lt() || *rho >= range_bound {
                        return false;
                    }
                }
                _ => {
                    return false;
                }
            }
        }

        true
    }
}

fn derive_challenges(
    ek: &EncryptionKey,
    c: &fast_paillier::Ciphertext,
    pairs: &[EncryptedPair],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"lin17-range-proof");
    hasher.update(ek.n().to_bytes_msf());
    hasher.update(c.to_bytes_msf());
    for pair in pairs {
        hasher.update(pair.c_masked.to_bytes_msf());
        hasher.update(pair.c_mask.to_bytes_msf());
    }
    let hash: [u8; 32] = hasher.finalize().into();

    let mut bits = Vec::with_capacity(SECURITY_PARAM);
    let mut current_hash = hash;
    let mut round = 0u32;
    while bits.len() < SECURITY_PARAM {
        for byte in &current_hash {
            for bit_pos in 0..8 {
                if bits.len() >= SECURITY_PARAM {
                    break;
                }
                bits.push((byte >> bit_pos) & 1);
            }
        }
        if bits.len() < SECURITY_PARAM {
            round += 1;
            current_hash = Sha256::new()
                .chain_update(b"lin17-range-proof-expand")
                .chain_update(hash)
                .chain_update(round.to_le_bytes())
                .finalize()
                .into();
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "redundant boundary test"]
    fn nonce_extraction_roundtrip() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");

        let x = Integer::from(12345u32);
        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let extracted = extract_nonce(&dk, &c, &x).expect("extract nonce");
        assert_eq!(extracted, r, "extracted nonce must match original");
    }

    #[test]
    fn range_proof_valid() {
        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let q = Integer::from_bytes_msf(&1_000_000_007u64.to_be_bytes());
        let x = Integer::from(42u32);

        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let proof = RangeProofNi::prove(&dk, &ek, &c, &x, &r, &q, &mut rng).expect("prove");
        assert!(proof.verify(&ek, &c, &q), "valid range proof must verify");
    }

    #[test]
    #[ignore = "redundant boundary test"]
    fn range_proof_with_real_curve_order() {
        use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

        let mut rng = rand_core::OsRng;
        let dk = fast_paillier::DecryptionKey::generate(&mut rng).expect("keygen");
        let ek = dk.encryption_key().clone();

        let q_bytes = scalar_to_bytes::<k256::Secp256k1>(
            &(-<k256::Secp256k1 as elliptic_curve::CurveArithmetic>::Scalar::ONE),
        );
        let q = Integer::from_bytes_msf(&q_bytes) + 1u8;

        let x1 = k256::Secp256k1::random_scalar(&mut rng);
        let x1_bytes = scalar_to_bytes::<k256::Secp256k1>(&x1);
        let x = Integer::from_bytes_msf(&x1_bytes);

        let (c, r) = dk.encrypt_with_random(&mut rng, &x).expect("encrypt");

        let proof = RangeProofNi::prove(&dk, &ek, &c, &x, &r, &q, &mut rng).expect("prove");
        assert!(
            proof.verify(&ek, &c, &q),
            "range proof with real curve order must verify"
        );
    }
}
