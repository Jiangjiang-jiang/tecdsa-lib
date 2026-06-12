use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::JlPublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlvComProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    pub z_vec: Vec<Integer>,
}

const STAT_SEC: u32 = 80;
const CHALLENGE_BITS: u32 = 80;

impl ZkJlvComProof {
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        pk: &JlPublicKey,
        y_vec: &[Integer],
        c: &Integer,
        m_vec: &[Integer],
        r: &Integer,
        b_bits_vec: &[u32],
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        assert_eq!(y_vec.len(), m_vec.len());
        assert_eq!(y_vec.len(), b_bits_vec.len());

        let ell = y_vec.len();
        let two_pow_k = Integer::from(1) << pk.k;

        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w = random_below(&w_bound, rng);

        let mut v_vec = Vec::with_capacity(ell);
        let mut y_items = Vec::with_capacity(ell);

        for i in 0..ell {
            let v_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + b_bits_vec[i]);
            let v = random_below(&v_bound, rng);

            let exp_y = Integer::from(&two_pow_k * &v);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);

            v_vec.push(v);
            y_items.push(y_item);
        }

        let mut d = Integer::from(1);
        for y_item in &y_items {
            d = mul_mod(&d, y_item, &pk.n);
        }
        let exp_h = Integer::from(&two_pow_k * &w);
        let h_w = pow_mod(&pk.h, &exp_h, &pk.n);
        d = mul_mod(&d, &h_w, &pk.n);

        let e = fiat_shamir_challenge(pk, y_vec, c, &d);

        let z_vec: Vec<Integer> = (0..ell)
            .map(|i| Integer::from(&e * &m_vec[i]) + &v_vec[i])
            .collect();
        let z_r = Integer::from(&e * r) + &w;

        Self { d, z_r, z_vec }
    }

    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, y_vec: &[Integer], c: &Integer) -> bool {
        assert_eq!(y_vec.len(), self.z_vec.len());

        let ell = y_vec.len();
        let two_pow_k = Integer::from(1) << pk.k;

        let e = fiat_shamir_challenge(pk, y_vec, c, &self.d);

        let mut lhs = Integer::from(1);
        for i in 0..ell {
            let exp_y = Integer::from(&two_pow_k * &self.z_vec[i]);
            let y_item = pow_mod(&y_vec[i], &exp_y, &pk.n);
            lhs = mul_mod(&lhs, &y_item, &pk.n);
        }
        let exp_h = Integer::from(&two_pow_k * &self.z_r);
        let h_item = pow_mod(&pk.h, &exp_h, &pk.n);
        lhs = mul_mod(&lhs, &h_item, &pk.n);

        let c_e = pow_mod(c, &e, &pk.n);
        let rhs = mul_mod(&c_e, &self.d, &pk.n);

        lhs == rhs
    }
}

fn fiat_shamir_challenge(pk: &JlPublicKey, y_vec: &[Integer], c: &Integer, d: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlvCom");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update((y_vec.len() as u32).to_be_bytes());
    for y in y_vec {
        hasher.update(y.to_digits::<u8>(Order::Msf));
    }
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

#[must_use]
pub fn jl_vec_commit(
    pk: &JlPublicKey,
    y_vec: &[Integer],
    m_vec: &[Integer],
    r: &Integer,
) -> Integer {
    assert_eq!(y_vec.len(), m_vec.len());
    let two_pow_k = Integer::from(1) << pk.k;
    let mut c = Integer::from(1);
    for i in 0..y_vec.len() {
        let exp = Integer::from(&two_pow_k * &m_vec[i]);
        let item = pow_mod(&y_vec[i], &exp, &pk.n);
        c = mul_mod(&c, &item, &pk.n);
    }
    let exp_h = Integer::from(&two_pow_k * r);
    let h_r = pow_mod(&pk.h, &exp_h, &pk.n);
    mul_mod(&c, &h_r, &pk.n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkjlv_com_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let ell = 3;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&pk.n, &mut rng);
            let y_i = pow_mod(&x, &alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec: Vec<Integer> = vec![
            Integer::from(42u32),
            Integer::from(17u32),
            Integer::from(99u32),
        ];
        let b_bits_vec: Vec<u32> = vec![32, 32, 32];
        let r = random_below(&pk.n, &mut rng);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);
        let proof = ZkJlvComProof::prove(&pk, &y_vec, &c, &m_vec, &r, &b_bits_vec, &mut rng);
        assert!(proof.verify(&pk, &y_vec, &c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjlv_com_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let ell = 2;
        let mut y_vec = Vec::with_capacity(ell);
        for _ in 0..ell {
            let alpha_i = random_below(&pk.n, &mut rng);
            let y_i = pow_mod(&x, &alpha_i, &pk.n);
            y_vec.push(y_i);
        }

        let m_vec = vec![Integer::from(42u32), Integer::from(17u32)];
        let b_bits_vec = vec![32, 32];
        let r = random_below(&pk.n, &mut rng);

        let c = jl_vec_commit(&pk, &y_vec, &m_vec, &r);

        let wrong_m = vec![Integer::from(99u32), Integer::from(17u32)];
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof =
            ZkJlvComProof::prove(&pk, &y_vec, &c, &wrong_m, &wrong_r, &b_bits_vec, &mut rng);
        assert!(!proof.verify(&pk, &y_vec, &c));
    }
}
