// SPDX-License-Identifier: MIT OR Apache-2.0
//! `FZero` functionality -- zero-sharing sub-protocol.
//!
//! Implements Functionality 3.4 (Zero Shares) from `DKLs23`.
//! Parties generate additive shares that sum to zero, which
//! are then used to rerandomize key shares during signing.
//!
//! # Protocol overview
//!
//! **Setup (during KeyGen, 2 rounds):**
//! 1. Each pair `(P_i, P_j)`: `P_i` generates a random 16-byte seed, commits
//!    via `SHA-256(salt || seed)`, and broadcasts the commitment.
//! 2. After exchange: both parties XOR their seeds to get a shared `seed_pair`.
//! 3. Store all seed pairs in a [`ZeroShareState`].
//!
//! **Per signing session (local computation, no communication):**
//! 1. For each counterparty `j` in the signing set, derive a fragment from the
//!    shared seed using a tagged hash, then add or subtract it depending on
//!    index ordering.
//! 2. The sum of all parties' output shares is guaranteed to be zero.

use elliptic_curve::{ops::Reduce, CurveArithmetic, Field, FieldBytes};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::soft_spoken::{tagged_hash, tagged_hash_as_scalar};

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Seed length in bytes (128-bit computational security).
const SEED_LEN: usize = 16;

/// Salt length in bytes (`2 * lambda_c` = 32 bytes).
const SALT_LEN: usize = 32;

/// Domain-separation tag for commitment hashing.
const TAG_COMMITMENT: &[u8] = b"tecdsa/fzero/commitment/v1";

/// Domain-separation tag for zero-share fragment derivation.
const TAG_ZERO_SHARE_FRAGMENT: &[u8] = b"tecdsa/fzero/fragment/v1";

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// 128-bit random seed.
pub type Seed = [u8; SEED_LEN];

/// SHA-256 commitment output.
pub type Commitment = [u8; 32];

/// Salt used in commitment scheme.
pub type Salt = [u8; SALT_LEN];

/// Represents the common seed a pair of parties shares after the setup phase.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SeedPair {
    /// `true` if the owning party has the lower index in the pair.
    pub lowest_index: bool,
    /// Index of the counterparty.
    pub counterparty_index: u16,
    /// XOR of both parties' seeds -- the shared secret.
    pub seed: Seed,
}

/// State held by a single party for generating zero shares.
///
/// Contains one [`SeedPair`] per counterparty established during keygen.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZeroShareState {
    /// Shared seed pairs, one per counterparty.
    pub seed_pairs: Vec<SeedPair>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Setup functions
// ──────────────────────────────────────────────────────────────────────────────

/// Generate a random seed and commit to it.
///
/// Returns `(seed, commitment, salt)`.  The commitment is
/// `SHA-256(salt || seed)`.  The caller should broadcast `commitment` first,
/// then reveal `seed` and `salt` later during decommitment.
pub fn generate_seed_with_commitment(rng: &mut impl CryptoRngCore) -> (Seed, Commitment, Salt) {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);

    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);

    let commitment = compute_commitment(&seed, &salt);
    (seed, commitment, salt)
}

/// Verify that `seed` matches the previously received `commitment` and `salt`.
///
/// Returns `true` if the commitment is valid.
pub fn verify_seed_commitment(seed: &Seed, commitment: &Commitment, salt: &Salt) -> bool {
    let expected = compute_commitment(seed, salt);
    bool::from(commitment.ct_eq(&expected))
}

/// Combine two seeds into a shared [`SeedPair`] by XOR.
///
/// `my_index` and `their_index` are 1-based party indices.
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

// ──────────────────────────────────────────────────────────────────────────────
// Per-session computation
// ──────────────────────────────────────────────────────────────────────────────

impl ZeroShareState {
    /// Construct a new [`ZeroShareState`] from the established seed pairs.
    pub fn new(seed_pairs: Vec<SeedPair>) -> Self {
        Self { seed_pairs }
    }

    /// Compute a zero-share for a specific signing session.
    ///
    /// `counterparties` lists the indices of participating counterparties
    /// (not including self).  `session_id` is a unique per-session identifier
    /// agreed upon by all participants.
    ///
    /// The output scalar, summed across all participating parties, equals zero.
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
            // Skip counterparties not in the current signing set.
            if !counterparties.contains(&seed_pair.counterparty_index) {
                continue;
            }

            // Derive a deterministic fragment from the shared seed and session id.
            let fragment =
                tagged_hash_as_scalar::<C>(TAG_ZERO_SHARE_FRAGMENT, &[session_id, &seed_pair.seed]);

            // The sign ensures that fragments cancel across parties:
            // if P_i has lowest_index for the (i,j) pair, P_i subtracts
            // while P_j (who does NOT have lowest_index) adds.
            if seed_pair.lowest_index {
                share -= fragment;
            } else {
                share += fragment;
            }
        }

        share
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Compute `commitment = tagged_hash(TAG_COMMITMENT, [salt, seed])`.
fn compute_commitment(seed: &Seed, salt: &Salt) -> Commitment {
    tagged_hash(TAG_COMMITMENT, &[salt.as_slice(), seed.as_slice()])
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::CurveArithmetic;
    use k256::Secp256k1;
    use rand_core::OsRng;

    type TestCurve = Secp256k1;
    type Scalar = <TestCurve as CurveArithmetic>::Scalar;

    /// Run the full setup protocol for `n` parties and return their
    /// `ZeroShareState` objects.
    fn setup_parties(n: u16) -> Vec<ZeroShareState> {
        let mut rng = OsRng;

        // Step 1: Each party generates one seed+commitment per counterparty.
        let mut seeds_and_commits: Vec<Vec<(Seed, Commitment, Salt)>> = Vec::new();
        for _ in 0..n {
            let mut party_data = Vec::new();
            for _ in 0..n {
                party_data.push(generate_seed_with_commitment(&mut rng));
            }
            seeds_and_commits.push(party_data);
        }

        // Step 2: Verify all commitments (simulating the broadcast round).
        for i in 0..n as usize {
            for j in 0..n as usize {
                let (ref seed, ref commitment, ref salt) = seeds_and_commits[i][j];
                assert!(
                    verify_seed_commitment(seed, commitment, salt),
                    "commitment verification failed for party {i} -> {j}"
                );
            }
        }

        // Step 3: Combine seeds into pairs and build state.
        let mut states = Vec::new();
        for i in 0..n {
            let mut pairs = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                let my_seed = &seeds_and_commits[i as usize][j as usize].0;
                let their_seed = &seeds_and_commits[j as usize][i as usize].0;
                // Party indices are 1-based.
                pairs.push(combine_seeds(i + 1, j + 1, my_seed, their_seed));
            }
            states.push(ZeroShareState::new(pairs));
        }

        states
    }

    /// 3 parties all participate -- verify sum of shares equals zero.
    #[test]
    fn test_zero_shares_3_parties() {
        let n: u16 = 3;
        let states = setup_parties(n);

        let session_id = b"test-session-3-parties";

        // All parties participate.
        let all_indices: Vec<u16> = (1..=n).collect();

        let mut shares: Vec<Scalar> = Vec::new();
        for i in 1..=n {
            // Counterparties = everyone except self.
            let counterparties: Vec<u16> =
                all_indices.iter().copied().filter(|&j| j != i).collect();
            let share = states[(i - 1) as usize].compute::<TestCurve>(&counterparties, session_id);
            shares.push(share);
        }

        let sum: Scalar = shares.iter().copied().sum();
        assert_eq!(sum, Scalar::ZERO, "shares of 3 parties must sum to zero");
    }

    /// 5 parties total, but only a subset of 3 participate.
    #[test]
    fn test_zero_shares_subset() {
        let n: u16 = 5;
        let states = setup_parties(n);

        let session_id = b"test-session-subset";

        // Only parties 1, 3, 5 participate.
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

    /// Valid seed passes commitment verification; tampered seed fails.
    #[test]
    fn test_commitment_verify() {
        let mut rng = OsRng;
        let (seed, commitment, salt) = generate_seed_with_commitment(&mut rng);

        // Valid seed should pass.
        assert!(verify_seed_commitment(&seed, &commitment, &salt));

        // Tampered seed should fail.
        let mut bad_seed = seed;
        bad_seed[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&bad_seed, &commitment, &salt),
            "tampered seed must not pass verification"
        );

        // Tampered salt should fail.
        let mut bad_salt = salt;
        bad_salt[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&seed, &commitment, &bad_salt),
            "tampered salt must not pass verification"
        );

        // Tampered commitment should fail.
        let mut bad_commitment = commitment;
        bad_commitment[0] ^= 0xFF;
        assert!(
            !verify_seed_commitment(&seed, &bad_commitment, &salt),
            "tampered commitment must not pass verification"
        );
    }

    /// Different session IDs must produce different shares.
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
