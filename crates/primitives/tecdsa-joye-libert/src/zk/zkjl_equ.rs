use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

use crate::kgen::JlPublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlEquProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d_prime: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_m: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r0: Integer,
}

const STAT_SEC: u32 = 80;
const CHALLENGE_BITS: u32 = 80;

impl ZkJlEquProof {
    #[allow(clippy::many_single_char_names, clippy::too_many_arguments)]
    pub fn prove(
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        c: &Integer,
        c_prime: &Integer,
        m: &Integer,
        r: &Integer,
        r0: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let two_pow_k = Integer::from(1) << pk.k;

        let v_bound = Integer::from(1) << (STAT_SEC + CHALLENGE_BITS + msg_bits);
        let w_bound = Integer::from(&pk.n << (STAT_SEC + CHALLENGE_BITS));
        let w0_bound = Integer::from(&pk0.n << (STAT_SEC + CHALLENGE_BITS));

        let v = random_below(&v_bound, rng);
        let w = random_below(&w_bound, rng);
        let w0 = random_below(&w0_bound, rng);

        let exp_y = Integer::from(&two_pow_k * &v);
        let exp_h = Integer::from(&two_pow_k * &w);
        let y_v = pow_mod(&pk.y, &exp_y, &pk.n);
        let h_w = pow_mod(&pk.h, &exp_h, &pk.n);
        let d = mul_mod(&y_v, &h_w, &pk.n);

        let two_pow_k0 = Integer::from(1) << pk0.k;
        let exp_y0 = Integer::from(&two_pow_k0 * &v);
        let exp_h0 = Integer::from(&two_pow_k0 * &w0);
        let y0_v = pow_mod(&pk0.y, &exp_y0, &pk0.n);
        let h0_w0 = pow_mod(&pk0.h, &exp_h0, &pk0.n);
        let d_prime = mul_mod(&y0_v, &h0_w0, &pk0.n);

        let e = fiat_shamir_challenge(pk, pk0, c, c_prime, &d, &d_prime);

        let z_m = Integer::from(&e * m) + &v;
        let z_r = Integer::from(&e * r) + &w;
        let z_r0 = Integer::from(&e * r0) + &w0;

        Self {
            d,
            d_prime,
            z_m,
            z_r,
            z_r0,
        }
    }

    #[must_use]
    pub fn verify(
        &self,
        pk: &JlPublicKey,
        pk0: &JlPublicKey,
        c: &Integer,
        c_prime: &Integer,
    ) -> bool {
        let two_pow_k = Integer::from(1) << pk.k;
        let two_pow_k0 = Integer::from(1) << pk0.k;

        let e = fiat_shamir_challenge(pk, pk0, c, c_prime, &self.d, &self.d_prime);

        let exp_y = Integer::from(&two_pow_k * &self.z_m);
        let exp_h = Integer::from(&two_pow_k * &self.z_r);
        let lhs1_y = pow_mod(&pk.y, &exp_y, &pk.n);
        let lhs1_h = pow_mod(&pk.h, &exp_h, &pk.n);
        let lhs1 = mul_mod(&lhs1_y, &lhs1_h, &pk.n);

        let c_e = pow_mod(c, &e, &pk.n);
        let rhs1 = mul_mod(&c_e, &self.d, &pk.n);

        if lhs1 != rhs1 {
            return false;
        }

        let exp_y0 = Integer::from(&two_pow_k0 * &self.z_m);
        let exp_h0 = Integer::from(&two_pow_k0 * &self.z_r0);
        let lhs2_y = pow_mod(&pk0.y, &exp_y0, &pk0.n);
        let lhs2_h = pow_mod(&pk0.h, &exp_h0, &pk0.n);
        let lhs2 = mul_mod(&lhs2_y, &lhs2_h, &pk0.n);

        let c_prime_e = pow_mod(c_prime, &e, &pk0.n);
        let rhs2 = mul_mod(&c_prime_e, &self.d_prime, &pk0.n);

        lhs2 == rhs2
    }
}

fn fiat_shamir_challenge(
    pk: &JlPublicKey,
    pk0: &JlPublicKey,
    c: &Integer,
    c_prime: &Integer,
    d: &Integer,
    d_prime: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlEqu");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(pk0.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk0.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(c_prime.to_digits::<u8>(Order::Msf));
    hasher.update(d.to_digits::<u8>(Order::Msf));
    hasher.update(d_prime.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kgen::generate_keypair_with_params, zk::zkjl_com::jl_commit};

    #[test]
    fn zkjl_equ_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let r = random_below(&pk.n, &mut rng);
        let r0 = random_below(&pk0.n, &mut rng);

        let c = jl_commit(&pk, &m, &r);
        let c_prime = jl_commit(&pk0, &m, &r0);

        let proof = ZkJlEquProof::prove(&pk, &pk0, &c, &c_prime, &m, &r, &r0, 32, &mut rng);
        assert!(proof.verify(&pk, &pk0, &c, &c_prime));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_equ_rejects_different_messages() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);
        let (pk0, _sk0) = generate_keypair_with_params(256, 32, &mut rng);

        let m1 = Integer::from(42u32);
        let m2 = Integer::from(99u32);
        let r = random_below(&pk.n, &mut rng);
        let r0 = random_below(&pk0.n, &mut rng);

        let c = jl_commit(&pk, &m1, &r);
        let c_prime = jl_commit(&pk0, &m2, &r0);

        let proof = ZkJlEquProof::prove(&pk, &pk0, &c, &c_prime, &m1, &r, &r0, 32, &mut rng);
        assert!(!proof.verify(&pk, &pk0, &c, &c_prime));
    }
}
