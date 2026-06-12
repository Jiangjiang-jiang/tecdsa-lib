use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_bigint::{mul_mod, pow_mod, random_below};

const REPEAT: usize = 80;
const STAT_SEC: u32 = 80;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkQr2kDlProof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub h: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub y: Integer,
    pub k: u32,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    a_vec: Vec<Integer>,
    #[serde(with = "tecdsa_bigint::int_wire::vec")]
    z_vec: Vec<Integer>,
}

impl ZkQr2kDlProof {
    pub fn prove(
        n: &Integer,
        k: u32,
        alpha: &Integer,
        h: &Integer,
        y: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let beta_bound = Integer::from(n << STAT_SEC);

        let mut a_vec = Vec::with_capacity(REPEAT);
        let mut beta_vec = Vec::with_capacity(REPEAT);

        for _ in 0..REPEAT {
            let beta = random_below(&beta_bound, rng);
            let a = pow_mod(h, &beta, n);
            a_vec.push(a);
            beta_vec.push(beta);
        }

        let e = compute_challenge(&a_vec);

        let mut z_vec = Vec::with_capacity(REPEAT);
        for i in 0..REPEAT {
            let z = if e.get_bit(i as u32) {
                Integer::from(&beta_vec[i] + alpha)
            } else {
                beta_vec[i].clone()
            };
            z_vec.push(z);
        }

        Self {
            h: h.clone(),
            n: n.clone(),
            y: y.clone(),
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
            let lhs = pow_mod(&self.h, &self.z_vec[i], &self.n);

            let rhs = if e.get_bit(i as u32) {
                let y_exp = pow_mod(&self.y, &two_pow_k, &self.n);
                mul_mod(&self.a_vec[i], &y_exp, &self.n)
            } else {
                self.a_vec[i].clone()
            };

            if lhs != rhs {
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
        h.update(b"ZkQr2kDl-a");
        h.update(a.to_digits::<u8>(Order::Msf));
        fs_vec.push(h.finalize());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"ZkQr2kDl-e");
    for fs in &fs_vec {
        hasher.update(fs);
    }
    let hash = hasher.finalize();
    Integer::from_digits(&hash, Order::Msf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkqr2kdl_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, sk, _x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let proof = ZkQr2kDlProof::prove(&pk.n, pk.k, &sk.alpha, &pk.h, &pk.y, &mut rng);
        assert!(proof.verify());
    }
}
