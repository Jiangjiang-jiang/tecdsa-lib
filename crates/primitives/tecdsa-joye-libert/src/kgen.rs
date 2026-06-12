use rand_core::CryptoRngCore;
use rug::{
    rand::{MutRandState, ThreadRandState},
    Complete, Integer,
};
use serde::{Deserialize, Serialize};
use tecdsa_bigint::{gen_pair, pow_mod, small_odd_primes, SyncRng};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JlPublicKey {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub n: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub y: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub h: Integer,
    pub k: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JlSecretKey {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub p: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub y_to_neg_pp: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub alpha: Integer,
}

impl Zeroize for JlSecretKey {
    fn zeroize(&mut self) {
        self.p = Integer::new();
        self.alpha = Integer::new();
    }
}

impl Drop for JlSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for JlSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlSecretKey")
            .field("p", &"[REDACTED]")
            .field("alpha", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SecurityLevel {
    Sec128,
    Sec192,
    Sec256,
}

impl SecurityLevel {
    #[must_use]
    pub const fn params(self) -> (u64, u32) {
        match self {
            Self::Sec128 => (1680, 256),
            Self::Sec192 => (3840, 384),
            Self::Sec256 => (7680, 512),
        }
    }
}

pub fn generate_keypair(
    level: SecurityLevel,
    rng: &mut impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey) {
    let (p_bits, k) = level.params();
    generate_keypair_with_params(p_bits, k, rng)
}

#[allow(clippy::many_single_char_names)]
pub fn generate_keypair_with_params(
    p_bits: u64,
    msg_space_bits: u32,
    rng: &mut impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey) {
    let (pk, sk, _) = generate_keypair_with_qnr(p_bits, msg_space_bits, rng);
    (pk, sk)
}

#[allow(clippy::many_single_char_names)]
pub fn generate_keypair_with_qnr(
    p_bits: u64,
    msg_space_bits: u32,
    rng: impl CryptoRngCore,
) -> (JlPublicKey, JlSecretKey, Integer) {
    let mut rng = SyncRng(rng);
    let rng = &mut ThreadRandState::new_custom(&mut rng);
    let primes = small_odd_primes(50_000);

    let b = p_bits as u32;
    let k = msg_space_bits;
    let (pp, p) = gen_pair(b - k, &(Integer::ONE << k).into(), 25, 15, &primes, rng);
    let (_, q) = gen_pair(b - 1, &Integer::from(2), 25, 15, &primes, rng);

    let n: Integer = (&p * &q).into();

    let qnr = choose_non_quadratic_residue(&p, &q, &n, rng);

    let mut alpha = n.clone().random_below(rng);
    alpha.set_bit(0, true);

    let gen_y = pow_mod(&qnr, &alpha, &n);

    let two_pow_k = Integer::from(1) << msg_space_bits;
    let elem_h = pow_mod(&qnr, &two_pow_k, &n);

    let y_to_neg_pp = gen_y
        .pow_mod_ref(&pp, &p)
        .unwrap()
        .complete()
        .invert(&p)
        .unwrap();

    let pk = JlPublicKey {
        n,
        y: gen_y,
        h: elem_h,
        k: msg_space_bits,
    };
    let sk = JlSecretKey {
        p,
        y_to_neg_pp,
        alpha,
    };

    (pk, sk, qnr)
}

fn choose_non_quadratic_residue(
    p: &Integer,
    q: &Integer,
    n: &Integer,
    rng: &mut impl MutRandState,
) -> Integer {
    loop {
        let x = n.clone().random_below(rng);
        if x.jacobi(p) == -1 && x.jacobi(q) == -1 {
            return x;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_keygen_produces_valid_structure() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair_with_params(256, 32, &mut rng);

        assert!(pk.n != 0);
        assert!(pk.n.is_divisible(&sk.p));
        assert_eq!(pk.k, 32);
        assert!(pk.y != 0);
        assert!(pk.h != 0);
    }
}
