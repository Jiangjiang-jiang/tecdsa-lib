// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trout online signing protocol (Round 2).
//!
//! Upon receiving all Round 1 broadcasts:
//! 1. Verify all eVRF proofs
//! 2. Verify R_{CL-EC} proofs (K_tilde_i encrypts same k_i as R_i)
//! 3. Verify R_{ComKwlg} proofs (knowledge of u_i, beta_i in U_i)
//! 4. Compute R = sum(R_j), r = x-coord(R)
//! 5. Compute Z_tilde_j from the Lagrange-scaled share encryptions
//! 6. Run Scaled Decryption on ({U_j}, {K_tilde_j}) -> u*k
//! 7. Run Scaled Decryption on ({U_j}, {Z_tilde_j}) -> u*(H(m)+r*x)
//! 8. Compute s = (u*k)^{-1} * u*(H(m)+r*x) = k^{-1}*(H(m)+r*x)
//! 9. Verify and output (r, s)
//!
//! ## Identifiable Abort (IA)
//!
//! In the IA variant, each party generates R_affCom proofs for their F_i
//! contributions during scaled decryption. If the final ECDSA signature
//! verification fails, these proofs can be checked individually to identify
//! the cheating party.
//!
//! ## Relationship to `MtABroadcast` trait
//!
//! Steps 6-7 (scaled decryption) correspond to the decode and aggregation
//! phases of [`tecdsa_protocol::MtABroadcast`] as implemented by
//! [`tecdsa_class_group::ScaledDecryptMtA`].  Specifically:
//!
//! - `crate::scaled_decrypt::compute_f_share` performs the same
//!   computation as [`ScaledDecryptMtA::decode`][tecdsa_class_group::ScaledDecryptMtA],
//!   computing $F_i = A_2^{b_i} \cdot A_1^{\beta_i} \cdot B^{-\alpha_i}$.
//!
//! - `crate::scaled_decrypt::aggregate_and_solve` performs the same
//!   computation as [`ScaledDecryptMtA::aggregate_f_shares`][tecdsa_class_group::ScaledDecryptMtA],
//!   composing all $F_i$ shares and extracting the discrete log.
//!
//! - `crate::scaled_decrypt::aggregate_ciphertext_components` and
//!   `crate::scaled_decrypt::aggregate_commitments` match
//!   [`ScaledDecryptMtA::aggregate`][tecdsa_class_group::ScaledDecryptMtA].
//!
//! This module uses the local `crate::scaled_decrypt` helpers directly
//! because (a) Trout runs two distinct scaled decryption instances with
//! different effective $\alpha$ values (one for $u \cdot k$, another for
//! $u \cdot (H(m) + rx)$ with Lagrange-scaled randomness), (b) the
//! intermediate `Qfi` elements are reused across both instances without
//! serialization, and (c) the IA variant requires `compute_f_share_with_proof`
//! which adds `R_{affCom}` proofs not modelled by the trait.

pub mod machine;

use rug::{integer::Order, Integer};
use tecdsa_class_group::{
    cl::ClSetup,
    scaled_decrypt::{
        aggregate_and_solve, aggregate_ciphertext_components, aggregate_commitments,
        compute_f_share, ScaledDecryptPartyInput, ScaledDecryptPublic,
    },
};
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::{qfi_from_abc, TroutError, TroutResult},
    key_share::TroutKeyShare,
    presign::types::TroutPresignOutput,
};

/// Execute the signing protocol (Round 2) given a message and presign output.
///
/// This runs the two scaled decryption instances and computes the final
/// ECDSA signature. All ZK proofs from Round 1 (R_{CL-EC}, R_{ComKwlg})
/// are verified before proceeding.
///
/// # Arguments
/// - `all_presigns`: presign outputs from ALL participating parties
/// - `message`: the message digest to sign
/// - `share`: this party's key share (for public key verification)
/// - `setup`: CL-HSM setup
/// - `cl_pk`: the joint CL public key
///
/// # Returns
/// The ECDSA signature `(r, s)`.
pub fn sign_round2(
    all_presigns: &[TroutPresignOutput],
    message: &DataToSign<k256::Secp256k1>,
    share: &TroutKeyShare,
    setup: &ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
) -> TroutResult<Signature<k256::Secp256k1>> {
    let _n = all_presigns.len();
    let r_scalar = all_presigns[0].r_scalar;
    let r_bytes = tecdsa_curve::conv::scalar_to_bytes(&r_scalar);
    let m_bytes = tecdsa_curve::conv::scalar_to_bytes(message.digest());

    // ---------------------------------------------------------------
    // Reconstruct per-party components from broadcasts
    // ---------------------------------------------------------------
    let broadcasts = &all_presigns[0].all_broadcasts;

    // ---------------------------------------------------------------
    // Verify R_{CL-EC} proofs: each K_tilde_i encrypts same k_i as R_i
    // ---------------------------------------------------------------
    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        let kt_ct = setup.ct_from_components(&c1, &c2)?;

        let cl_ec_ok = bcast
            .pi_cl_ec
            .verify(setup, cl_pk, &kt_ct, &bcast.r_i_bytes)?;
        if !cl_ec_ok {
            return Err(TroutError::ProofFailed(format!(
                "R_CL-EC proof failed for party {}",
                bcast.party_index
            )));
        }
    }

    // ---------------------------------------------------------------
    // Verify R_{ComKwlg} proofs: knowledge of (u_i, beta_i) in U_i
    // U_i = h^beta_i * pk^u_i, so verify with pk as the second base.
    // ---------------------------------------------------------------
    let pk_elt = cl_pk.elt();
    for bcast in broadcasts {
        let (a, b, c) = &bcast.u_com_abc;
        let u_com = qfi_from_abc(a, b, c)?;

        let com_kwlg_ok = bcast.pi_com_kwlg.verify_with_base(setup, &u_com, pk_elt)?;
        if !com_kwlg_ok {
            return Err(TroutError::ProofFailed(format!(
                "R_ComKwlg proof failed for party {}",
                bcast.party_index
            )));
        }
    }

    // ---------------------------------------------------------------
    // Reconstruct ciphertext and commitment components
    // ---------------------------------------------------------------

    // K_tilde encryption components
    let mut kt_components = Vec::new();
    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        kt_components.push((c1, c2));
    }

    // U_i commitments
    let mut u_coms = Vec::new();
    for bcast in broadcasts {
        let (a, b, c) = &bcast.u_com_abc;
        let u = qfi_from_abc(a, b, c)?;
        u_coms.push(u);
    }

    // Lagrange-scaled C_tilde_i components
    let mut ct_scaled_components = Vec::new();
    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.ct_scaled_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.ct_scaled_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        ct_scaled_components.push((c1, c2));
    }

    // ---------------------------------------------------------------
    // Compute Z_tilde_j = r * C_tilde_j_scaled for each party.
    // Then add Enc(0, H(m)) to the first party's Z_tilde.
    // ---------------------------------------------------------------
    let mut z_components = Vec::new();
    for (c1, c2) in &ct_scaled_components {
        let z_c1 = setup.exp_bytes(c1, &r_bytes)?;
        let z_c2 = setup.exp_bytes(c2, &r_bytes)?;
        z_components.push((z_c1, z_c2));
    }

    // Add Enc(0, H(m)) = (identity, f^m) to the first party's Z_tilde.
    // We replace z_components[0] in-place: keep c1, update c2.
    let f_m = setup.power_of_f_bytes(&m_bytes)?;
    let (old_c1, old_c2) = z_components.remove(0);
    let new_z0_c2 = setup.compose(&old_c2, &f_m)?;
    z_components.insert(0, (old_c1, new_z0_c2));

    // ---------------------------------------------------------------
    // Scaled Decryption #1: compute u * k
    //
    // A = {K_tilde_j = Enc(alpha_j, k_j)}
    // B = {U_j = Com(beta_j, u_j)}
    // ---------------------------------------------------------------
    let (kt_a1, kt_a2) = aggregate_ciphertext_components(setup, &kt_components)?;
    let u_b_agg = aggregate_commitments(setup, &u_coms)?;

    let sd1_public = ScaledDecryptPublic {
        a1: kt_a1,
        a2: kt_a2,
        b_agg: u_b_agg,
    };

    let sd1_inputs: Vec<ScaledDecryptPartyInput> = all_presigns
        .iter()
        .map(|p| ScaledDecryptPartyInput {
            alpha_i: p.alpha_i.clone(),
            beta_i: p.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes(&p.u_i),
        })
        .collect();

    let mut f1_shares = Vec::new();
    for input in &sd1_inputs {
        let f_i = compute_f_share(setup, input, &sd1_public)?;
        f1_shares.push(f_i);
    }
    let uk = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&aggregate_and_solve(
        setup, &f1_shares,
    )?);

    // ---------------------------------------------------------------
    // Scaled Decryption #2: compute u * (H(m) + r*x)
    //
    // A = {Z_tilde_j} with effective alpha = r * L_j * delta_j
    // B = {U_j = Com(beta_j, u_j)} (same as SD1)
    // ---------------------------------------------------------------
    let (z_a1, z_a2) = aggregate_ciphertext_components(setup, &z_components)?;
    let u_b_agg2 = aggregate_commitments(setup, &u_coms)?;

    let sd2_public = ScaledDecryptPublic {
        a1: z_a1,
        a2: z_a2,
        b_agg: u_b_agg2,
    };

    // Compute effective alpha for each party's Z_tilde_j.
    // alpha_z_j = r * L_j * delta_j = r * l_i_delta_i
    let sd2_inputs: Vec<ScaledDecryptPartyInput> = all_presigns
        .iter()
        .map(|p| {
            let r_val =
                Integer::from_digits(&tecdsa_curve::conv::scalar_to_bytes(&r_scalar), Order::Msf);
            let lid_val = Integer::from_digits(&p.l_i_delta_i, Order::Msf);
            let alpha_z = Integer::from(&r_val * &lid_val).to_digits::<u8>(Order::Msf);

            ScaledDecryptPartyInput {
                alpha_i: alpha_z,
                beta_i: p.beta_i.clone(),
                b_i: tecdsa_curve::conv::scalar_to_bytes(&p.u_i),
            }
        })
        .collect();

    let mut f2_shares = Vec::new();
    for input in &sd2_inputs {
        let f_i = compute_f_share(setup, input, &sd2_public)?;
        f2_shares.push(f_i);
    }
    let u_mx = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&aggregate_and_solve(
        setup, &f2_shares,
    )?);

    // ---------------------------------------------------------------
    // Compute s = (u*k)^{-1} * u*(H(m)+r*x)
    // ---------------------------------------------------------------
    let uk_inv = uk
        .invert()
        .into_option()
        .ok_or_else(|| TroutError::EcdsaFailed("u*k is zero, cannot invert".into()))?;

    let s = uk_inv * u_mx;
    let s = low_s_normalize::<k256::Secp256k1>(s);

    let sig = Signature { r: r_scalar, s };

    // Verify the signature
    verify_ecdsa::<k256::Secp256k1>(&sig, &share.public_key, message)
        .map_err(|e| TroutError::EcdsaFailed(format!("final verification: {e}")))?;

    Ok(sig)
}

/// Identify the cheating party when ECDSA verification fails (IA variant).
///
/// Given the per-party F_i shares and their R_affCom proofs, verifies each
/// proof individually to determine which party submitted an incorrect F_i.
///
/// # Arguments
/// - `f_shares`: per-party scaled decryption shares with proofs
/// - `setup`: CL-HSM setup
/// - `cl_pk`: the joint CL public key
/// - `ct_in`: the aggregated encryption ciphertext
/// - `u_coms`: per-party commitment elements U_i
///
/// # Returns
/// The 0-based index of the first party whose proof fails, or `None` if all
/// proofs verify (indicating the issue is elsewhere).
pub fn identify_cheater(
    f_shares: &[tecdsa_class_group::scaled_decrypt::ScaledDecryptShare],
    setup: &ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
    ct_in: &tecdsa_class_group::cl::ClCiphertext,
    u_coms: &[tecdsa_class_group::cl::Qfi],
) -> Option<usize> {
    for (i, share) in f_shares.iter().enumerate() {
        if let Some(ref proof) = share.pi_aff_com {
            let identity = match setup.identity() {
                Ok(id) => id,
                Err(_) => return Some(i),
            };
            let ct_out = match setup.ct_from_components(&identity, &share.f_i) {
                Ok(ct) => ct,
                Err(_) => return Some(i),
            };
            match proof.verify(setup, cl_pk, ct_in, &ct_out, &u_coms[i]) {
                Ok(true) => continue,
                _ => return Some(i),
            }
        }
    }
    None
}
