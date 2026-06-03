// SPDX-License-Identifier: MIT OR Apache-2.0
//! XAL23 presigning protocol (offline phase).
//!
//! The presigning protocol produces a presignature that can later be combined
//! with a message hash to produce a full ECDSA signature.
//!
//! The protocol follows the GG18 structure but uses JL-based MtA:
//!
//! Round 1: Each party samples k_i, gamma_i, broadcasts commitment to g^{gamma_i}.
//! Round 2: Decommit g^{gamma_i}, run JL MtA for k_i * gamma_j products.
//! Round 3: Compute delta_i = k_i * gamma_i + sum(alpha_ij + beta_ij), broadcast delta_i.
//! Round 4: Reconstruct delta = sum(delta_i), compute R = (sum g^{gamma_i})^{delta^{-1}},
//!          compute sigma_i = k_i * w_i + sum(mu_ij + nu_ij).

#![allow(non_snake_case)]

pub mod machine;
pub mod msg;
mod types;

use elliptic_curve::{
    group::{Curve as CurveGroup, Group},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
pub use machine::Xal23PresignMachine;
pub use msg::Xal23PresignMsg;
use num_bigint::BigUint;
use num_traits::Zero;
use tecdsa_curve::{
    conv::{biguint_to_scalar, curve_order, scalar_to_biguint},
    TecdsaCurve,
};
use tecdsa_joye_libert::mta::{JlMtA, JlMtaSetup};
use tecdsa_protocol::{MtA, PartyId};
pub use types::Xal23Presignature;

use crate::key_share::Xal23KeyShare;

/// Runs the complete presigning protocol for all parties (orchestrated locally).
///
/// This is a simulation-friendly API that computes the presignature for
/// a given subset of signers. In production, each round's messages would
/// be sent over the network.
///
/// Uses default statistical security parameters (s=t=40).
/// Defaults to `JlMtA` as the MtA backend.
///
/// # Arguments
///
/// * `key_shares` - Key shares for all signing parties
/// * `signer_indices` - Indices of the signing parties (0-based, into `key_shares`)
///
/// # Returns
///
/// A vector of presignatures, one per signer.
pub fn presign_all<C: TecdsaCurve>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    presign_all_with_sec(key_shares, signer_indices, 40, 40, rng)
}

/// Runs the complete presigning protocol with configurable statistical security.
///
/// `s` and `t` are the MtA statistical security parameters. The JL message
/// space parameter `k` must satisfy `k >= 2 * ceil(log2(q)) + 2*s + t + 2`.
///
/// Use `s=t=40` for production. Smaller values can be used for testing.
/// Defaults to `JlMtA` as the MtA backend.
pub fn presign_all_with_sec<C: TecdsaCurve>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    s: u32,
    t: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Build JlMtaSetup for each party from the key shares.
    // mta_setups[i][j]: pk = peer j's key (for encryption/decryption),
    //                   pk0 = local party i's key (for ZkJlEquProof commitment),
    //                   sk = peer j's secret key (simulation only).
    let setups: Vec<Vec<JlMtaSetup>> = signer_indices
        .iter()
        .map(|&idx| {
            signer_indices
                .iter()
                .map(|&peer_idx| JlMtaSetup {
                    pk: key_shares[peer_idx].jl_pks[peer_idx].clone(),
                    pk0: key_shares[idx].jl_pks[idx].clone(),
                    sk: key_shares[peer_idx].jl_sk.clone(),
                    s,
                    t,
                })
                .collect()
        })
        .collect();

    presign_all_generic::<C, JlMtA>(key_shares, signer_indices, &setups, rng)
}

/// Runs the complete presigning protocol, generic over the MtA backend.
///
/// This is the core implementation. The MtA backend `M` determines which
/// encryption scheme is used for the multiplicative-to-additive conversion.
///
/// # Arguments
///
/// * `key_shares` - Key shares for all signing parties
/// * `signer_indices` - Indices of the signing parties (0-based, into `key_shares`)
/// * `mta_setups` - MtA setup material: `mta_setups[i][j]` is the setup for
///   the MtA between local party `i` and peer party `j` (using peer j's keys)
/// * `rng` - Cryptographic RNG
pub fn presign_all_generic<C: TecdsaCurve, M: MtA>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    mta_setups: &[Vec<M::Setup>],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = signer_indices.len();
    let q = curve_order::<C>();
    let q_bytes = q.to_bytes_be();

    // -----------------------------------------------------------------------
    // Round 1: Sample k_i, gamma_i, compute G_gamma_i = gamma_i * G
    // -----------------------------------------------------------------------
    let mut k_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut gamma_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut g_gamma_vec: Vec<C::ProjectivePoint> = Vec::with_capacity(n);

    for _ in 0..n {
        let k_i = C::random_scalar(rng);
        let gamma_i = C::random_scalar(rng);
        let g_gamma_i = C::generator() * gamma_i;
        k_vec.push(k_i);
        gamma_vec.push(gamma_i);
        g_gamma_vec.push(g_gamma_i);
    }

    // -----------------------------------------------------------------------
    // Round 2: MtA for k_i * gamma_j (produces delta shares)
    //          MtA for k_i * w_j (produces sigma shares)
    //
    // For each pair (i, j) where i != j:
    //   - MtA(k_i, gamma_j) produces (alpha_ij, beta_ij)
    //     s.t. alpha_ij + beta_ij = k_i * gamma_j (mod q)
    //   - MtA(k_i, w_j) produces (mu_ij, nu_ij)
    //     s.t. mu_ij + nu_ij = k_i * w_j (mod q)
    // -----------------------------------------------------------------------

    // Compute signing shares w_i.
    // For additive sharing (all n parties required): w_i = x_i directly.
    // For Shamir sharing (t-of-n): w_i = lambda_i * x_i where lambda_i
    // is the Lagrange coefficient.
    //
    // Our trusted dealer keygen uses additive sharing, so w_i = x_i.
    let w_vec: Vec<C::Scalar> = signer_indices
        .iter()
        .map(|&idx| key_shares[idx].secret_share)
        .collect();

    // alpha_ij, beta_ij for k_i * gamma_j
    let mut alpha_kg = vec![vec![BigUint::zero(); n]; n];
    let mut beta_kg = vec![vec![BigUint::zero(); n]; n];

    // mu_ij, nu_ij for k_i * w_j
    let mut mu_kw = vec![vec![BigUint::zero(); n]; n];
    let mut nu_kw = vec![vec![BigUint::zero(); n]; n];

    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }

            let setup_j = &mta_setups[i][j];

            // MtA for k_i * gamma_j:
            //   Trait "sender" (P2) encrypts gamma_j (step 1)
            //   Trait "receiver" (P1) does affine with k_i, gets alpha (step 2)
            //   Trait "sender" (P2) decrypts, gets beta (step 3)
            {
                let k_i_bytes = scalar_to_biguint::<C>(&k_vec[i]).to_bytes_be();
                let gamma_j_bytes = scalar_to_biguint::<C>(&gamma_vec[j]).to_bytes_be();

                // Step 1: encrypt gamma_j
                let (sender_msg, sender_state) =
                    M::sender_encrypt(setup_j, &gamma_j_bytes, &q_bytes, rng)
                        .expect("MtA sender_encrypt failed");

                // Step 2: affine with k_i, get alpha
                let (receiver_msg, alpha_bytes) =
                    M::receiver_compute(setup_j, &k_i_bytes, &q_bytes, &sender_msg, rng)
                        .expect("MtA receiver_compute failed");

                // Step 3: decrypt, get beta
                let beta_bytes = M::sender_decrypt(setup_j, &sender_state, &q_bytes, &receiver_msg)
                    .expect("MtA sender_decrypt failed");

                alpha_kg[i][j] = BigUint::from_bytes_be(&alpha_bytes);
                beta_kg[i][j] = BigUint::from_bytes_be(&beta_bytes);
            }

            // MtA for k_i * w_j:
            {
                let k_i_bytes = scalar_to_biguint::<C>(&k_vec[i]).to_bytes_be();
                let w_j_bytes = scalar_to_biguint::<C>(&w_vec[j]).to_bytes_be();

                let (sender_msg, sender_state) =
                    M::sender_encrypt(setup_j, &w_j_bytes, &q_bytes, rng)
                        .expect("MtA sender_encrypt failed");

                let (receiver_msg, mu_bytes) =
                    M::receiver_compute(setup_j, &k_i_bytes, &q_bytes, &sender_msg, rng)
                        .expect("MtA receiver_compute failed");

                let nu_bytes = M::sender_decrypt(setup_j, &sender_state, &q_bytes, &receiver_msg)
                    .expect("MtA sender_decrypt failed");

                mu_kw[i][j] = BigUint::from_bytes_be(&mu_bytes);
                nu_kw[i][j] = BigUint::from_bytes_be(&nu_bytes);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Round 3: Compute delta_i = k_i * gamma_i + sum_j(alpha_ij + beta_ji)
    //
    // alpha_kg[i][j] = alpha from MtA(k_i, gamma_j) — i's share as sender
    // beta_kg[j][i]  = beta from MtA(k_j, gamma_i)  — i's share as receiver
    // -----------------------------------------------------------------------
    let mut delta_vec: Vec<C::Scalar> = Vec::with_capacity(n);

    for i in 0..n {
        let mut delta_i = k_vec[i] * gamma_vec[i]; // k_i * gamma_i
        for j in 0..n {
            if i == j {
                continue;
            }
            // i's alpha from MtA(k_i, gamma_j) — i was sender
            delta_i += biguint_to_scalar::<C>(&alpha_kg[i][j]);
            // i's beta from MtA(k_j, gamma_i) — i was receiver
            delta_i += biguint_to_scalar::<C>(&beta_kg[j][i]);
        }
        delta_vec.push(delta_i);
    }

    // -----------------------------------------------------------------------
    // Round 4: Reconstruct delta, compute R, compute sigma_i
    // -----------------------------------------------------------------------

    // delta = sum(delta_i) = k * gamma
    let delta: C::Scalar = delta_vec.iter().fold(C::Scalar::ZERO, |acc, d| acc + d);

    let delta_inv = delta
        .invert()
        .into_option()
        .expect("delta should be invertible");

    // Gamma = sum g^{gamma_i}
    let Gamma: C::ProjectivePoint = g_gamma_vec
        .iter()
        .fold(C::ProjectivePoint::identity(), |acc, g| acc + g);

    // R = Gamma * delta^{-1} = g^{gamma / delta} = g^{1/k}
    let R = Gamma * delta_inv;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    // sigma_i = k_i * w_i + sum_j(mu_ij + nu_ji)
    let mut sigma_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    for i in 0..n {
        let mut sigma_i = k_vec[i] * w_vec[i]; // k_i * w_i
        for j in 0..n {
            if i == j {
                continue;
            }
            // i's mu from MtA(k_i, w_j) — i was sender
            sigma_i += biguint_to_scalar::<C>(&mu_kw[i][j]);
            // i's nu from MtA(k_j, w_i) — i was receiver
            sigma_i += biguint_to_scalar::<C>(&nu_kw[j][i]);
        }
        sigma_vec.push(sigma_i);
    }

    // Assemble presignatures
    let mut presigs = Vec::with_capacity(n);
    for i in 0..n {
        presigs.push(Xal23Presignature {
            R,
            r,
            k_i: k_vec[i],
            sigma_i: sigma_vec[i],
            public_key: key_shares[signer_indices[i]].public_key,
            my_id: PartyId(signer_indices[i] as u16),
            signer_parties: signer_indices
                .iter()
                .map(|&idx| PartyId(idx as u16))
                .collect(),
        });
    }

    presigs
}

/// Compute the Lagrange coefficient lambda_i for party at `party_index`
/// given the set of all signer indices.
///
/// Used when key shares are generated with Shamir secret sharing (t-of-n).
/// With additive sharing (n-of-n), lambda_i = 1 and this function is not needed.
#[allow(dead_code)]
fn compute_lagrange_coeff<C: TecdsaCurve>(party_index: usize, signer_indices: &[usize]) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x_i = C::Scalar::from(party_index as u64 + 1); // 1-indexed for Lagrange
    let mut num = C::Scalar::ONE;
    let mut den = C::Scalar::ONE;
    for &j_idx in signer_indices {
        if j_idx == party_index {
            continue;
        }
        let x_j = C::Scalar::from(j_idx as u64 + 1);
        num *= x_j;
        den *= x_j - x_i;
    }
    let den_inv = den
        .invert()
        .into_option()
        .expect("Lagrange denominator should be invertible");
    num * den_inv
}
