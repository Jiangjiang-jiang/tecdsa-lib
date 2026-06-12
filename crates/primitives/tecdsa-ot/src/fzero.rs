use elliptic_curve::{ops::Reduce, CurveArithmetic, Field, FieldBytes};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::soft_spoken::{tagged_hash, tagged_hash_as_scalar};

const SEED_LEN: usize = 16;

const SALT_LEN: usize = 32;

const TAG_COMMITMENT: &[u8] = b"tecdsa/fzero/commitment/v1";

const TAG_ZERO_SHARE_FRAGMENT: &[u8] = b"tecdsa/fzero/fragment/v1";

pub type Seed = [u8; SEED_LEN];

pub type Commitment = [u8; 32];

pub type Salt = [u8; SALT_LEN];

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SeedPair {
    pub lowest_index: bool,
    pub counterparty_index: u16,
    pub seed: Seed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroShareState {
    pub seed_pairs: Vec<SeedPair>,
}

pub fn generate_seed_with_commitment(rng: &mut impl CryptoRngCore) -> (Seed, Commitment, Salt) {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let commitment = compute_commitment(&seed, &salt);
    (seed, commitment, salt)
}

pub fn verify_seed_commitment(seed: &Seed, commitment: &Commitment, salt: &Salt) -> bool {
    let expected = compute_commitment(seed, salt);
    bool::from(commitment.ct_eq(&expected))
}

pub fn combine_seeds(
    my_index: u16,
    their_index: u16,
    my_seed: &Seed,
    their_seed: &Seed,
) -> SeedPair {
    let mut combined = [0u8; SEED_LEN];
    for i in 0..SEED_LEN {
        combined[i] = my_seed[i] ^ their_seed[i];
    }
    SeedPair {
        lowest_index: my_index <= their_index,
        counterparty_index: their_index,
        seed: combined,
    }
}

impl ZeroShareState {
    pub fn new(seed_pairs: Vec<SeedPair>) -> Self {
        Self { seed_pairs }
    }

    pub fn compute<C: CurveArithmetic>(
        &self,
        counterparties: &[u16],
        session_id: &[u8],
    ) -> C::Scalar
    where
        C::Scalar: Reduce<FieldBytes<C>>,
    {
        let mut share = <C::Scalar as Field>::ZERO;

        for seed_pair in &self.seed_pairs {
            if !counterparties.contains(&seed_pair.counterparty_index) {
                continue;
            }

            let fragment =
                tagged_hash_as_scalar::<C>(TAG_ZERO_SHARE_FRAGMENT, &[session_id, &seed_pair.seed]);

            if seed_pair.lowest_index {
                share -= fragment;
            } else {
                share += fragment;
            }
        }

        share
    }
}

fn compute_commitment(seed: &Seed, salt: &Salt) -> Commitment {
    tagged_hash(TAG_COMMITMENT, &[salt.as_slice(), seed.as_slice()])
}

#[cfg(test)]
mod tests {
    use elliptic_curve::CurveArithmetic;
    use k256::Secp256k1;
    use rand_core::OsRng;

    use super::*;

    type TestCurve = Secp256k1;
    type Scalar = <TestCurve as CurveArithmetic>::Scalar;

    fn setup_parties(n: u16) -> Vec<ZeroShareState> {
        let mut rng = OsRng;

        let mut seeds_and_commits: Vec<Vec<(Seed, Commitment, Salt)>> = Vec::new();
        for _ in 0..n {
            let mut party_data = Vec::new();
            for _ in 0..n {
                party_data.push(generate_seed_with_commitment(&mut rng));
            }
            seeds_and_commits.push(party_data);
        }

        for i in 0..n as usize {
            for j in 0..n as usize {
                let (ref seed, ref commitment, ref salt) = seeds_and_commits[i][j];
                assert!(
                    verify_seed_commitment(seed, commitment, salt),
                    "commitment verification failed for party {i} -> {j}"
                );
            }
        }

        let mut states = Vec::new();
        for i in 0..n {
            let mut pairs = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                let my_seed = &seeds_and_commits[i as usize][j as usize].0;
                let their_seed = &seeds_and_commits[j as usize][i as usize].0;
                pairs.push(combine_seeds(i + 1, j + 1, my_seed, their_seed));
            }
            states.push(ZeroShareState::new(pairs));
        }

        states
    }

    #[test]
    fn test_zero_shares_3_parties() {
        let n: u16 = 3;
        let states = setup_parties(n);

        let session_id = b"test-session-3-parties";

        let all_indices: Vec<u16> = (1..=n).collect();

        let mut shares: Vec<Scalar> = Vec::new();
        for i in 1..=n {
            let counterparties: Vec<u16> =
                all_indices.iter().copied().filter(|&j| j != i).collect();
            let share = states[(i - 1) as usize].compute::<TestCurve>(&counterparties, session_id);
            shares.push(share);
        }

        let sum: Scalar = shares.iter().copied().sum();
        assert_eq!(sum, Scalar::ZERO, "shares of 3 parties must sum to zero");
    }

    #[test]
    fn test_zero_shares_subset() {
        let n: u16 = 5;
        let states = setup_parties(n);

        let session_id = b"test-session-subset";

        let participating: Vec<u16> = vec![1, 3, 5];

        let mut shares: Vec<Scalar> = Vec::new();
        for &i in &participating {
            let counterparties: Vec<u16> =
                participating.iter().copied().filter(|&j| j != i).collect();
            let share = states[(i - 1) as usize].compute::<TestCurve>(&counterparties, session_id);
            shares.push(share);
        }

        let sum: Scalar = shares.iter().copied().sum();
        assert_eq!(
            sum,
            Scalar::ZERO,
            "shares of subset {participating:?} must sum to zero"
        );
    }

    #[test]
    fn test_commitment_verify() {
        let mut rng = OsRng;
        let (seed, commitment, salt) = generate_seed_with_commitment(&mut rng);

        assert!(verify_seed_commitment(&seed, &commitment, &salt));

        let mut bad_seed = seed;
        bad_seed[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&bad_seed, &commitment, &salt),
            "tampered seed must not pass verification"
        );

        let mut bad_salt = salt;
        bad_salt[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&seed, &commitment, &bad_salt),
            "tampered salt must not pass verification"
        );

        let mut bad_commitment = commitment;
        bad_commitment[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&seed, &bad_commitment, &salt),
            "tampered commitment must not pass verification"
        );
    }

    #[test]
    fn test_different_sessions_different_shares() {
        let states = setup_parties(3);
        let counterparties = vec![2, 3];

        let share_a = states[0].compute::<TestCurve>(&counterparties, b"session-A");
        let share_b = states[0].compute::<TestCurve>(&counterparties, b"session-B");

        assert_ne!(
            share_a, share_b,
            "different session IDs must produce different shares"
        );
    }
}
