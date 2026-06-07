// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trout key generation.
//!
//! In the Trout protocol, key generation produces:
//! 1. Shamir secret sharing of x -> {x_i}
//! 2. Each party's CL encryption of their share: C_tilde_i = Enc(delta_i, x_i)
//! 3. Each party's eVRF key pair
//!
//! This module provides two modes:
//! - `trusted_dealer_keygen`: single-shot trusted dealer (for testing).
//! - `TroutKeygenMachine`: interactive 3-round DKG (Protocol 3.1).

pub mod machine;
pub mod msg;
pub mod rounds;

pub use machine::TroutKeygenMachine;
pub use msg::TroutKeygenMsg;
use rand_core::CryptoRngCore;
use tecdsa_class_group::cl::ClSetup;
use tecdsa_curve::TecdsaCurve;
use tecdsa_evrf::EvrfSecretKey;

use crate::{
    error::{qfi_to_abc, TroutResult},
    key_share::TroutKeyShare,
};

/// Run trusted-dealer key generation for the Trout protocol.
///
/// Generates a signing key `x`, splits it into Shamir shares `{x_i}`,
/// encrypts each share under the joint CL public key, and generates
/// eVRF key pairs for each party.
///
/// # Arguments
/// - `setup`: CL-HSM setup (shared across all parties).
/// - `seed`: CL setup seed string (for recreating setup from key shares).
/// - `n`: total number of parties.
/// - `t`: reconstruction threshold (t parties needed to sign).
/// - `use_128bit`: whether to use 128-bit security CL params.
/// - `rng`: cryptographic RNG.
///
/// # Returns
/// A vector of `TroutKeyShare`, one per party.
pub fn trusted_dealer_keygen(
    setup: &mut ClSetup,
    seed: &str,
    n: u16,
    t: u16,
    use_128bit: bool,
    rng: &mut impl CryptoRngCore,
) -> TroutResult<Vec<TroutKeyShare>> {
    // 1. Generate the signing key x and split via Shamir
    let x = <k256::Secp256k1 as TecdsaCurve>::random_scalar(rng);
    let shares = tecdsa_vss::shamir::split::<k256::Secp256k1>(&x, t, n, rng);

    // Joint public key X = x * G
    let public_key = k256::Secp256k1::generator() * x;

    // Public verification shares X_j = x_j * G
    let public_shares: Vec<k256::ProjectivePoint> = shares
        .iter()
        .map(|s| k256::Secp256k1::generator() * s.value)
        .collect();

    // 2. Generate eVRF key pairs for each party
    let mut evrf_sks = Vec::new();
    let mut evrf_pks = Vec::new();
    for _ in 0..n {
        let (sk, pk) = EvrfSecretKey::<k256::Secp256k1>::generate(rng);
        evrf_sks.push(sk);
        evrf_pks.push(pk);
    }

    // 3. Generate joint CL public key Y_cl
    let (_cl_sk, cl_pk) = setup.keygen()?;
    let cl_pk_elt = &cl_pk.elt();
    let cl_pk_abc = qfi_to_abc(cl_pk_elt)?;

    // 4. Encrypt each share under Y_cl with random delta_i
    let mut ct_components = Vec::new();
    let mut deltas = Vec::new();
    for share in &shares {
        let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&share.value);

        // Generate random delta_i (encryption randomness)
        let (sk_tmp, _) = setup.keygen()?;
        let delta_i = setup.sk_to_bytes(&sk_tmp)?;

        // C_tilde_i = Enc(delta_i, x_i)
        let ct = setup.encrypt_with_r_bytes(&cl_pk, &x_i_bytes, &delta_i)?;
        let (c1, c2) = setup.ct_components(&ct)?;

        // Serialise QFI components
        let (c1_a, c1_b, c1_c) = qfi_to_abc(&c1)?;
        let (c2_a, c2_b, c2_c) = qfi_to_abc(&c2)?;
        ct_components.push((c1_a, c1_b, c1_c, c2_a, c2_b, c2_c));
        deltas.push(delta_i);
    }

    // 5. Build key shares
    let mut key_shares = Vec::new();
    for i in 0..n as usize {
        key_shares.push(TroutKeyShare {
            party_index: shares[i].index,
            secret_share: shares[i].value,
            delta_i: deltas[i].clone(),
            evrf_sk: evrf_sks.remove(0),
            evrf_pk: evrf_pks[i].clone(),
            all_evrf_pks: evrf_pks.clone(),
            public_key,
            public_shares: public_shares.clone(),
            ct_share_components: ct_components[i].clone(),
            all_ct_share_components: ct_components.clone(),
            cl_pk_abc: cl_pk_abc.clone(),
            cl_setup_seed: seed.to_string(),
            use_128bit_security: use_128bit,
            threshold: t,
            total: n,
        });
    }

    Ok(key_shares)
}
