// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the XAL23 threshold ECDSA protocol.
//!
//! Each party holds:
//! - A secret share `x_i` of the ECDSA signing key `x`
//! - A JL key pair `(pk_jl, sk_jl)` for MtA operations
//! - The joint ECDSA public key `Y = x * G`
//! - The set of all parties' JL public keys

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_joye_libert::kgen::{JlPublicKey, JlSecretKey};
use zeroize::Zeroize;

/// Feldman VSS setup parameters.
#[derive(Debug, Clone)]
pub struct VssSetup {
    /// The threshold parameter `t`: at least `t + 1` shares are needed to sign.
    pub threshold: u16,
    /// Total number of parties `n`.
    pub total: u16,
}

/// A single party's key share produced by the XAL23 key generation.
///
/// Contains the party's secret share `x_i`, the joint public key `Y`,
/// JL keys for MtA, and public verification shares for all parties.
#[derive(Clone)]
pub struct Xal23KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's index (0-based).
    pub party_index: u16,
    /// Secret share `x_i` of the ECDSA signing key.
    pub secret_share: C::Scalar,
    /// Joint ECDSA public key `Y = x * G`.
    pub public_key: C::ProjectivePoint,
    /// Public verification shares `Y_j = x_j * G` for each party.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// VSS parameters (threshold, total).
    pub vss_setup: VssSetup,
    /// This party's JL secret key.
    pub jl_sk: JlSecretKey,
    /// JL public keys for all parties.
    pub jl_pks: Vec<JlPublicKey>,
}

impl<C: TecdsaCurve> Zeroize for Xal23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

impl<C: TecdsaCurve> std::fmt::Debug for Xal23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xal23KeyShare")
            .field("party_index", &self.party_index)
            .field("secret_share", &"[REDACTED]")
            .field("vss_setup", &self.vss_setup)
            .finish()
    }
}

/// Trusted dealer key generation for testing.
///
/// Generates key shares for `n` parties with threshold `t` using a trusted
/// dealer (no interactive protocol). Each party also gets a JL key pair.
///
/// For simplicity this uses additive secret sharing (requiring all n parties).
/// A proper implementation would use Feldman VSS for t-of-n threshold.
///
/// # Panics
///
/// Panics if `n < 2`.
pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    n: u16,
    t: u16,
    jl_p_bits: u64,
    jl_k: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23KeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::Field;

    assert!(n >= 2, "need at least 2 parties");
    assert!(t >= 1, "threshold must be >= 1");

    // Generate the master secret key
    let x = C::random_scalar(rng);
    let Y = C::generator() * x;

    // Additive sharing: x = x_1 + x_2 + ... + x_n
    let mut shares = Vec::with_capacity(n as usize);
    let mut sum = C::Scalar::ZERO;
    for _ in 0..(n - 1) {
        let x_i = C::random_scalar(rng);
        sum += x_i;
        shares.push(x_i);
    }
    // Last share = x - sum(others)
    shares.push(x - sum);

    // Compute public shares
    let public_shares: Vec<C::ProjectivePoint> =
        shares.iter().map(|xi| C::generator() * *xi).collect();

    // Generate JL key pairs for all parties
    let mut jl_pks = Vec::with_capacity(n as usize);
    let mut jl_sks = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (pk, sk) = tecdsa_joye_libert::kgen::generate_keypair_with_params(jl_p_bits, jl_k, rng);
        jl_pks.push(pk);
        jl_sks.push(sk);
    }

    // Assemble key shares
    let mut key_shares = Vec::with_capacity(n as usize);
    for i in 0..n {
        let idx = i as usize;
        key_shares.push(Xal23KeyShare {
            party_index: i,
            secret_share: shares[idx],
            public_key: Y,
            public_shares: public_shares.clone(),
            vss_setup: VssSetup {
                threshold: t,
                total: n,
            },
            jl_sk: jl_sks[idx].clone(),
            jl_pks: jl_pks.clone(),
        });
    }

    key_shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_dealer_produces_valid_shares() {
        let mut rng = rand::thread_rng();
        // Small JL params for unit test speed (not cryptographically meaningful)
        let shares = trusted_dealer_keygen::<k256::Secp256k1>(3, 1, 256, 128, &mut rng);

        assert_eq!(shares.len(), 3);

        // All parties should have the same public key
        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[1].public_key, shares[2].public_key);

        // Sum of secret shares should reconstruct the signing key
        let sum: k256::Scalar = shares
            .iter()
            .fold(k256::Scalar::ZERO, |acc, s| acc + s.secret_share);
        let reconstructed_pk = k256::ProjectivePoint::GENERATOR * sum;
        assert_eq!(reconstructed_pk, shares[0].public_key);
    }
}
