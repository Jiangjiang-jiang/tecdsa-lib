use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, multi_exp, pow_mod, random_below};

use crate::kgen::JlPublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlAffProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_a: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_alpha: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
}

const STAT_SEC: u32 = 80;
const CHALLENGE_BITS: u32 = 80;

impl ZkJlAffProof {
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn prove(
        pk: &JlPublicKey,
        c_base: &Integer,
        c_aff: &Integer,
        a: &Integer,
        alpha: &Integer,
        r: &Integer,
        b1_bits: u32,
        b2_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let v1_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + b1_bits);
        let v2_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + b2_bits);
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));

        let v1 = random_below(&v1_bound, rng);
        let v2 = random_below(&v2_bound, rng);
        let w = random_below(&w_bound, rng);

        let d = multi_exp(&[c_base, &pk.y, &pk.h], &[&v1, &v2, &w], &pk.n);

        let e = fiat_shamir_challenge(pk, c_base, c_aff, &d);

        let z_a = Integer::from(&e * a) + &v1;
        let z_alpha = Integer::from(&e * alpha) + &v2;
        let z_r = Integer::from(&e * r) + &w;

        Self {
            d,
            z_a,
            z_alpha,
            z_r,
        }
    }

    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, c_base: &Integer, c_aff: &Integer) -> bool {
        let e = fiat_shamir_challenge(pk, c_base, c_aff, &self.d);

        let lhs = multi_exp(
            &[c_base, &pk.y, &pk.h],
            &[&self.z_a, &self.z_alpha, &self.z_r],
            &pk.n,
        );

        let c_aff_e = pow_mod(c_aff, &e, &pk.n);
        let rhs = mul_mod(&c_aff_e, &self.d, &pk.n);

        lhs == rhs
    }
}

fn fiat_shamir_challenge(
    pk: &JlPublicKey,
    c_base: &Integer,
    c_aff: &Integer,
    d: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlAff");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c_base.to_digits::<u8>(Order::Msf));
    hasher.update(c_aff.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enc_dec::encrypt, kgen::generate_keypair_with_params};

    #[test]
    fn zkjl_aff_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let b = Integer::from(7u32);
        let (ct_b, _r_b) = encrypt(&pk, &b, &mut rng);

        let a = Integer::from(5u32);
        let alpha = Integer::from(13u32);
        let r = random_below(&pk.n, &mut rng);

        let c_a = pow_mod(&ct_b.c, &a, &pk.n);
        let y_alpha = pow_mod(&pk.y, &alpha, &pk.n);
        let h_r = pow_mod(&pk.h, &r, &pk.n);
        let c_aff = mul_mod(&mul_mod(&c_a, &y_alpha, &pk.n), &h_r, &pk.n);

        let proof = ZkJlAffProof::prove(&pk, &ct_b.c, &c_aff, &a, &alpha, &r, 32, 32, &mut rng);
        assert!(proof.verify(&pk, &ct_b.c, &c_aff));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_aff_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let b = Integer::from(7u32);
        let (ct_b, _r_b) = encrypt(&pk, &b, &mut rng);

        let a = Integer::from(5u32);
        let alpha = Integer::from(13u32);
        let r = random_below(&pk.n, &mut rng);

        let c_a = pow_mod(&ct_b.c, &a, &pk.n);
        let y_alpha = pow_mod(&pk.y, &alpha, &pk.n);
        let h_r = pow_mod(&pk.h, &r, &pk.n);
        let c_aff = mul_mod(&mul_mod(&c_a, &y_alpha, &pk.n), &h_r, &pk.n);

        let wrong_a = Integer::from(99u32);
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof = ZkJlAffProof::prove(
            &pk, &ct_b.c, &c_aff, &wrong_a, &alpha, &wrong_r, 32, 32, &mut rng,
        );
        assert!(!proof.verify(&pk, &ct_b.c, &c_aff));
    }
}
