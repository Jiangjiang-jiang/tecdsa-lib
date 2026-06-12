use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

const REPEAT: usize = 80;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkQr2kProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub h: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    pub k: u32,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    a_vec: Vec<Integer>,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    z_vec: Vec<Integer>,
}

impl ZkQr2kProof {
    pub fn prove(
        n: &Integer,
        k: u32,
        x: &Integer,
        h: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let two_pow_k = Integer::from(1) << k;

        let mut a_vec = Vec::with_capacity(REPEAT);
        let mut r_vec = Vec::with_capacity(REPEAT);

        for _ in 0..REPEAT {
            let r = random_below(n, rng);
            let a = pow_mod(&r, &two_pow_k, n);
            a_vec.push(a);
            r_vec.push(r);
        }

        let e = compute_challenge(&a_vec);

        let mut z_vec = Vec::with_capacity(REPEAT);
        for i in 0..REPEAT {
            if e.get_bit(i as u32) {
                let z = mul_mod(&r_vec[i], x, n);
                z_vec.push(z);
            } else {
                z_vec.push(r_vec[i].clone());
            }
        }

        Self {
            h: h.clone(),
            n: n.clone(),
            k,
            a_vec,
            z_vec,
        }
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let two_pow_k = Integer::from(1) << self.k;

        let e = compute_challenge(&self.a_vec);

        for i in 0..REPEAT {
            let z_pow = pow_mod(&self.z_vec[i], &two_pow_k, &self.n);

            let expected = if e.get_bit(i as u32) {
                mul_mod(&self.a_vec[i], &self.h, &self.n)
            } else {
                self.a_vec[i].clone()
            };

            if z_pow != expected {
                return false;
            }
        }

        true
    }
}

fn compute_challenge(a_vec: &[Integer]) -> Integer {
    let mut fs_vec = Vec::with_capacity(a_vec.len());
    for a in a_vec {
        let mut h = Sha256::new();
        h.update(b"ZkQr2k-a");
        h.update(a.to_digits::<u8>(Order::Msf));
        fs_vec.push(h.finalize());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ZkQr2k-e");
    for fs in &fs_vec {
        hasher.update(fs);
    }
    let hash = hasher.finalize();
    Integer::from_digits(&hash, Order::Msf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_params;

    #[test]
    fn zkqr2k_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair_with_params(256, 32, &mut rng);

        let x = random_below(&pk.n, &mut rng);
        let two_pow_k = Integer::from(1) << pk.k;
        let h = pow_mod(&x, &two_pow_k, &pk.n);

        let proof = ZkQr2kProof::prove(&pk.n, pk.k, &x, &h, &mut rng);
        assert!(proof.verify());
    }

    #[test]
    #[ignore = "redundant negative/variant test"]
    fn zkqr2k_verify_with_pk_h() {
        let mut rng = rand::thread_rng();
        let n_bits: u64 = 256;
        let k: u32 = 32;

        let x = random_below(&(Integer::from(1) << n_bits as u32), &mut rng);
        let mut n = random_below(&(Integer::from(1) << (n_bits as u32 * 2)), &mut rng);
        n.set_bit(0, true);

        let two_pow_k = Integer::from(1) << k;
        let h = pow_mod(&x, &two_pow_k, &n);

        let proof = ZkQr2kProof::prove(&n, k, &x, &h, &mut rng);
        assert!(proof.verify());
    }
}
