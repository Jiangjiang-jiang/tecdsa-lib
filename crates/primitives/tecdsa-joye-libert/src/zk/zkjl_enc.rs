use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, multi_exp, pow_mod, random_below};

use crate::kgen::JlPublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlEncProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub a: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_m: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z_r: Integer,
}

const CHALLENGE_BITS: u32 = 128;

impl ZkJlEncProof {
    #[allow(clippy::many_single_char_names)]
    pub fn prove(
        pk: &JlPublicKey,
        ct: &Integer,
        msg: &Integer,
        rand: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        let v_bound = Integer::from(1) << (msg_bits + stat_sec);
        let w_bound = Integer::from(&pk.n << stat_sec);

        let blind_v = random_below(&v_bound, rng);
        let blind_w = random_below(&w_bound, rng);

        let commit_a = multi_exp(&[&pk.y, &pk.h], &[&blind_v, &blind_w], &pk.n);

        let challenge = fiat_shamir_challenge(pk, ct, &commit_a);

        let z_m = &blind_v + Integer::from(&challenge * msg);
        let z_r = &blind_w + Integer::from(&challenge * rand);

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    #[must_use]
    pub fn verify(&self, pk: &JlPublicKey, ct: &Integer) -> bool {
        let challenge = fiat_shamir_challenge(pk, ct, &self.a);

        let lhs = multi_exp(&[&pk.y, &pk.h], &[&self.z_m, &self.z_r], &pk.n);

        let c_e = pow_mod(ct, &challenge, &pk.n);
        let rhs = mul_mod(&self.a, &c_e, &pk.n);

        lhs == rhs
    }
}

fn fiat_shamir_challenge(pk: &JlPublicKey, c: &Integer, a: &Integer) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(a.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

fn fiat_shamir_challenge_with_prefix(
    prefix: &[u8],
    pk: &JlPublicKey,
    c: &Integer,
    a: &Integer,
) -> Integer {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(b"ZkJlEnc");
    hasher.update(pk.n.to_digits::<u8>(Order::Msf));
    hasher.update(pk.y.to_digits::<u8>(Order::Msf));
    hasher.update(pk.h.to_digits::<u8>(Order::Msf));
    hasher.update(pk.k.to_be_bytes());
    hasher.update(c.to_digits::<u8>(Order::Msf));
    hasher.update(a.to_digits::<u8>(Order::Msf));
    let hash = hasher.finalize();

    Integer::from_digits(&hash, Order::Msf).keep_bits(CHALLENGE_BITS)
}

impl ZkJlEncProof {
    #[allow(clippy::many_single_char_names)]
    pub fn prove_with_prefix(
        prefix: &[u8],
        pk: &JlPublicKey,
        ct: &Integer,
        msg: &Integer,
        rand: &Integer,
        msg_bits: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let stat_sec = 80u32;

        let v_bound = Integer::from(1) << (msg_bits + stat_sec);
        let w_bound = Integer::from(&pk.n << stat_sec);

        let blind_v = random_below(&v_bound, rng);
        let blind_w = random_below(&w_bound, rng);

        let commit_a = multi_exp(&[&pk.y, &pk.h], &[&blind_v, &blind_w], &pk.n);

        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &commit_a);

        let z_m = &blind_v + Integer::from(&challenge * msg);
        let z_r = &blind_w + Integer::from(&challenge * rand);

        Self {
            a: commit_a,
            z_m,
            z_r,
        }
    }

    #[must_use]
    pub fn verify_with_prefix(&self, prefix: &[u8], pk: &JlPublicKey, ct: &Integer) -> bool {
        let challenge = fiat_shamir_challenge_with_prefix(prefix, pk, ct, &self.a);

        let lhs = multi_exp(&[&pk.y, &pk.h], &[&self.z_m, &self.z_r], &pk.n);

        let c_e = pow_mod(ct, &challenge, &pk.n);
        let rhs = mul_mod(&self.a, &c_e, &pk.n);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enc_dec::encrypt, kgen::generate_keypair_with_params};

    #[test]
    fn zkjl_enc_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify(&pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_rejects_wrong_witness() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, _r) = encrypt(&pk, &m, &mut rng);

        let wrong_m = Integer::from(99u32);
        let wrong_r = random_below(&pk.n, &mut rng);
        let proof = ZkJlEncProof::prove(&pk, &ct.c, &wrong_m, &wrong_r, 32, &mut rng);
        assert!(!proof.verify(&pk, &ct.c));
    }

    #[test]
    fn zkjl_enc_with_prefix_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let prefix = b"session-1::party-2::round-3";
        let proof = ZkJlEncProof::prove_with_prefix(prefix, &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(proof.verify_with_prefix(prefix, &pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_with_prefix_rejects_wrong_prefix() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let proof = ZkJlEncProof::prove_with_prefix(b"prefix-A", &pk, &ct.c, &m, &r, 32, &mut rng);
        assert!(!proof.verify_with_prefix(b"prefix-B", &pk, &ct.c));
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkjl_enc_rejects_mutated_proof() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let m = Integer::from(42u32);
        let (ct, r) = encrypt(&pk, &m, &mut rng);

        let mut proof = ZkJlEncProof::prove(&pk, &ct.c, &m, &r, 32, &mut rng);

        proof.z_m += 1;

        assert!(
            !proof.verify(&pk, &ct.c),
            "verification must reject a proof with mutated z_m response"
        );
    }
}
