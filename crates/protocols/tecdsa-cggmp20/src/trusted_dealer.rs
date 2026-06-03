// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trusted dealer for key import: splits a pre-existing secret key into threshold shares.
//!
//! This module implements a simple utility function that uses Feldman VSS to split
//! a pre-existing ECDSA secret key into threshold shares without requiring interactive
//! key generation (DKG).

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_vss::feldman;

use crate::key_share::{Cggmp20CoreKeyShare, VssSetup};

/// Import an existing secret key into threshold shares using Feldman VSS.
///
/// Given a secret key and parameters `(threshold, n)`, produces `n` core key shares
/// such that any `threshold` of them can reconstruct the original secret key.
///
/// # Arguments
/// * `secret_key` - The ECDSA secret key to import.
/// * `threshold` - Minimum number of parties required for signing.
/// * `n` - Total number of parties receiving shares.
/// * `rng` - Cryptographic random number generator.
///
/// # Returns
/// A vector of `Cggmp20CoreKeyShare<C>` values, one per party, each containing:
/// - The party's secret share
/// - The joint public key `secret_key * G`
/// - All parties' public verification shares
/// - VSS configuration (threshold and total)
///
/// # Panics
/// Panics if `threshold == 0` or `threshold > n`.
pub fn deal<C: TecdsaCurve>(
    secret_key: &<C as CurveArithmetic>::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Vec<Cggmp20CoreKeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Use Feldman VSS to split the secret key into shares
    // (commitments are only used for verification in other contexts)
    let (shares, _commitments) = feldman::split::<C>(secret_key, threshold, n, rng);

    // Compute the joint public key
    let public_key = C::generator() * secret_key;

    // Compute public shares: for each share, compute share.value * G
    let public_shares: Vec<C::ProjectivePoint> = shares
        .iter()
        .map(|share| C::generator() * share.value)
        .collect();

    // Build the core key shares
    shares
        .into_iter()
        .map(|share| Cggmp20CoreKeyShare {
            party_index: share.index - 1, // Convert from 1-based to 0-based indexing
            secret_share: share.value,
            public_key,
            public_shares: public_shares.clone(),
            vss_setup: VssSetup {
                threshold,
                total: n,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn trusted_dealer_produces_valid_shares() {
        let mut rng = rand_core::OsRng;

        // Generate a random secret key
        let secret_key = Secp256k1::random_scalar(&mut rng);

        // Deal shares: threshold=2, n=3
        let shares = deal::<Secp256k1>(&secret_key, 2, 3, &mut rng);

        // Assert: exactly 3 shares
        assert_eq!(shares.len(), 3);

        // Assert: all shares have the same public key equal to secret_key * G
        let expected_public_key = Secp256k1::generator() * secret_key;
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.party_index, i as u16);
            assert_eq!(share.public_key, expected_public_key);
            assert_eq!(share.vss_setup.threshold, 2);
            assert_eq!(share.vss_setup.total, 3);
        }

        // Assert: public_shares[i] == secret_share[i] * G for each party
        for (i, share) in shares.iter().enumerate() {
            let expected_public_share = Secp256k1::generator() * share.secret_share;
            assert_eq!(share.public_shares[i], expected_public_share);
        }
    }
}
