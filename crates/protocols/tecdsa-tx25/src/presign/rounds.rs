// SPDX-License-Identifier: MIT OR Apache-2.0
//! TX25 presign round state structs and transition logic.

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup, Qfi},
    zk::{r_dec_dl::RDecDlProof, r_enc::REncProof, r_m_aff_dl_ec::RMAffDlEcProof, r_sh::RShProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use super::{
    msg::{
        R2Payload, R2PerPartyMtA, SerRDecDlProof, SerRMAffDlEcProof, SerializedClCt, SerializedQfi,
        Tx25PresignMsg,
    },
    KeyMaterial, Tx25Presignature,
};
use crate::{
    mpmta::{mpmta_round2, mpmta_verify_round2, MpmtaRound2Output},
    pvss::{pvss_decrypt_share_full, pvss_verify},
};

// ---------------------------------------------------------------------------
// Received data (internal, reconstructed from messages)
// ---------------------------------------------------------------------------

/// Received Round 1 data from a single party.
pub(crate) struct ReceivedR1 {
    /// MPMtA Round 1 ciphertext (C_gamma_j).
    pub(crate) c_gamma: ClCiphertext,
    /// MPMtA Round 1 R_Enc proof.
    pub(crate) r_enc_proof: REncProof,
    /// PVSS c1 = h^rho.
    pub(crate) pvss_c1: Qfi,
    /// PVSS c2_j for each party.
    pub(crate) pvss_c2s: Vec<Qfi>,
    /// PVSS R_Sh proof.
    pub(crate) pvss_proof: RShProof,
}

/// Received Round 2 data from a single party.
#[allow(dead_code)]
pub(crate) struct ReceivedR2 {
    /// Per-counterparty MtA output ciphertexts for k*gamma.
    pub(crate) kg_c_alphas: Vec<ClCiphertext>,
    /// Per-counterparty MtA output ciphertexts for x*gamma.
    pub(crate) xg_c_alphas: Vec<ClCiphertext>,
    /// Beta points B_{j,nu} for k*gamma.
    pub(crate) b_points: Vec<k256::ProjectivePoint>,
    /// Beta-hat points B_hat_{j,nu} for x*gamma.
    pub(crate) b_hat_points: Vec<k256::ProjectivePoint>,
    /// R_j = k_j * G.
    pub(crate) r_point: k256::ProjectivePoint,
    /// Partial decryption pd = c1^{sk} for R_Dec_DL verification.
    pub(crate) pd: Qfi,
    /// The c1 used to compute pd.
    pub(crate) pd_c1: Qfi,
    /// R_Dec_DL proof.
    pub(crate) dec_dl_proof: RDecDlProof,
    /// R_m_AffDL_Ec proof for k*gamma.
    pub(crate) kg_proof: RMAffDlEcProof,
    /// R_m_AffDL_Ec proof for x*gamma.
    pub(crate) xg_proof: RMAffDlEcProof,
}

// ---------------------------------------------------------------------------
// State machine internal states
// ---------------------------------------------------------------------------

/// Round 1 state: waiting for Round 1 messages from all parties.
pub(crate) struct Round1State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) gamma_i: k256::Scalar,
    /// Own PVSS secret share (k_{i,i} from own polynomial).
    pub(crate) own_pvss_share: k256::Scalar,
    /// Received Round 1 messages (including self).
    pub(crate) received: BTreeMap<PartyId, ReceivedR1>,
    pub(crate) outgoing: Vec<Outgoing<Tx25PresignMsg>>,
}

/// Round 2 state: waiting for Round 2 messages from other parties.
pub(crate) struct Round2State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) gamma_i: k256::Scalar,
    pub(crate) k_i: k256::Scalar,
    /// All parties' C_gamma ciphertexts from Round 1 (for MPMtA verification).
    pub(crate) all_c_gammas: Vec<ClCiphertext>,
    /// Our MPMtA Round 2 output for k*gamma.
    pub(crate) kg_mta: MpmtaRound2Output,
    /// Our MPMtA Round 2 output for x*gamma.
    pub(crate) xg_mta: MpmtaRound2Output,
    /// Received Round 2 messages (from other parties).
    pub(crate) received: BTreeMap<PartyId, ReceivedR2>,
    pub(crate) outgoing: Vec<Outgoing<Tx25PresignMsg>>,
}

/// The internal round state for the presign state machine.
pub(crate) enum PresignRound {
    Round1(Round1State),
    Round2(Round2State),
    Done(Tx25Presignature),
    Poisoned,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deserialize a compressed EC point from bytes.
pub(crate) fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

/// Get this party's index (0-based) in the all_parties list.
pub(crate) fn my_idx(all_parties: &[PartyId], my_id: PartyId) -> Option<usize> {
    all_parties.iter().position(|p| *p == my_id)
}

/// Number of other parties.
pub(crate) fn n_others(all_parties: &[PartyId]) -> usize {
    all_parties.len() - 1
}

// ---------------------------------------------------------------------------
// Round 1 -> Round 2 transition
// ---------------------------------------------------------------------------

/// Transition from Round 1 to Round 2.
///
/// After receiving all Round 1 messages:
/// 1. Verify R_Enc proofs (MPMtA1) and R_Sh proofs (PVSS).
/// 2. ShareComb: decrypt own PVSS shares to get k_i, produce R_Dec_DL proof.
/// 3. MPMtA2 for k*gamma and x*gamma.
/// 4. Queue Round 2 broadcast.
pub(crate) fn transition_r1_to_r2(
    mut state: Round1State,
    setup: &mut ClSetup,
    key_mat: &KeyMaterial,
) -> tecdsa_core::Result<Round2State> {
    let my_idx_val = my_idx(&state.all_parties, state.my_id)
        .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
    let n = state.all_parties.len();
    let mut rng = rand::thread_rng();
    let party_ids_u16: Vec<u16> = state.all_parties.iter().map(|p| p.0).collect();

    // --- Step 1: Verify proofs ---
    for (&party_j, r1) in &state.received {
        if party_j == state.my_id {
            continue;
        }

        // Verify R_Enc proof: ciphertext is well-formed encryption.
        let j_idx = my_idx(&state.all_parties, party_j)
            .ok_or_else(|| TecdsaError::Other(format!("party {party_j} not found")))?;
        let pk_j = &key_mat.raw_pks[j_idx];
        let r_enc_ok = r1
            .r_enc_proof
            .verify(setup, pk_j, &r1.c_gamma)
            .map_err(|e| {
                TecdsaError::Other(format!("R_Enc verify failed for party {party_j}: {e}"))
            })?;
        if !r_enc_ok {
            return Err(TecdsaError::Other(format!(
                "R_Enc proof verification failed for party {party_j}"
            )));
        }

        // Verify R_Sh proof: PVSS shares are from a valid polynomial.
        let pvss_ok = pvss_verify(
            setup,
            &party_ids_u16,
            &key_mat.raw_pks,
            key_mat.threshold,
            &r1.pvss_c1,
            &r1.pvss_c2s,
            &r1.pvss_proof,
        )
        .map_err(|e| TecdsaError::Other(format!("PVSS verify failed for party {party_j}: {e}")))?;
        if !pvss_ok {
            return Err(TecdsaError::Other(format!(
                "R_Sh proof verification failed for party {party_j}"
            )));
        }
    }

    // --- Step 2: ShareComb ---
    // k_i = sum_j share_{i,j} where share_{i,j} is party j's PVSS
    // share for party i.
    let sk_raw = setup
        .sk_from_bytes(&key_mat.sk_decimal)
        .map_err(|e| TecdsaError::Other(format!("sk_from_decimal: {e}")))?;

    let mut k_i = state.own_pvss_share; // Start with own PVSS share.

    for (&party_j, r1) in &state.received {
        if party_j == state.my_id {
            continue;
        }

        // Party j distributed PVSS shares. Our share is c2s[my_idx_val].
        let c2_my = &r1.pvss_c2s[my_idx_val];

        let share_output = pvss_decrypt_share_full(setup, &sk_raw, &r1.pvss_c1, c2_my)
            .map_err(|e| TecdsaError::Other(format!("PVSS decrypt from party {party_j}: {e}")))?;

        k_i += share_output.share;
    }

    // R_i = k_i * G
    let r_point_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;

    // Generate R_Dec_DL proof for one representative decryption.
    // We use the first non-self party's PVSS ciphertext as representative.
    // The pd and pd_c1 are included in the R2 message for verification.
    let my_pk_raw = &key_mat.raw_pks[my_idx_val];
    let mut dec_dl_data: Option<(RDecDlProof, Qfi, Qfi)> = None;

    for (&party_j, r1) in &state.received {
        if party_j == state.my_id {
            continue;
        }
        let c2_my = &r1.pvss_c2s[my_idx_val];
        let ct_repr = setup
            .ct_from_components(&r1.pvss_c1, c2_my)
            .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;
        let pd = setup
            .exp_bytes(&r1.pvss_c1, &key_mat.sk_decimal)
            .map_err(|e| TecdsaError::Other(format!("partial_dec: {e}")))?;

        let proof = RDecDlProof::prove(setup, my_pk_raw, &ct_repr, &pd, &key_mat.sk_decimal)
            .map_err(|e| TecdsaError::Other(format!("R_Dec_DL prove: {e}")))?;

        // Copy the c1 for inclusion in the message via binary round-trip.
        let c1_bytes = r1.pvss_c1.to_bytes();
        let c1_copy = Qfi::from_bytes(&c1_bytes);

        dec_dl_data = Some((proof, pd, c1_copy));
        break; // One proof is sufficient as a representative.
    }

    // Fallback for single-party case (no other parties).
    let (dec_dl_proof, dec_dl_pd, dec_dl_c1) = match dec_dl_data {
        Some(data) => data,
        None => {
            let map_cl = |e| TecdsaError::Other(format!("CL fallback: {e}"));
            let id = setup.identity().map_err(map_cl)?;
            let id2 = setup.identity().map_err(map_cl)?;
            let id3 = setup.identity().map_err(map_cl)?;
            let dummy_ct = setup.ct_from_components(&id, &id2).map_err(map_cl)?;
            let proof = RDecDlProof::prove(setup, my_pk_raw, &dummy_ct, &id3, &key_mat.sk_decimal)
                .map_err(map_cl)?;
            let pd = setup.identity().map_err(map_cl)?;
            let c1 = setup.identity().map_err(map_cl)?;
            (proof, pd, c1)
        }
    };

    // --- Step 3: MPMtA Round 2 ---
    // Collect all C_gamma ciphertexts in party order.
    let mut all_c_gammas: Vec<ClCiphertext> = Vec::with_capacity(n);
    for &party_j in &state.all_parties {
        let r1 = state
            .received
            .get(&party_j)
            .ok_or_else(|| TecdsaError::Other(format!("missing R1 data from party {party_j}")))?;
        // Reconstruct the ciphertext from the received data.
        // We need to serialize and re-deserialize because ClCiphertext
        // doesn't implement Clone. We use the ct_components + ct_from_components
        // round-trip.
        let (c1, c2) = setup
            .ct_components(&r1.c_gamma)
            .map_err(|e| TecdsaError::Other(format!("ct_components: {e}")))?;
        let ct_copy = setup
            .ct_from_components(&c1, &c2)
            .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;
        all_c_gammas.push(ct_copy);
    }

    // MPMtA Round 2 for k*gamma.
    let k_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
    let kg_mta = mpmta_round2(
        setup,
        &party_ids_u16,
        my_idx_val,
        &key_mat.raw_pks,
        &all_c_gammas,
        &k_bytes,
        &mut rng,
    )
    .map_err(|e| TecdsaError::Other(format!("MPMtA2 k*gamma: {e}")))?;

    // MPMtA Round 2 for x*gamma.
    let x_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&key_mat.x_i);
    let xg_mta = mpmta_round2(
        setup,
        &party_ids_u16,
        my_idx_val,
        &key_mat.raw_pks,
        &all_c_gammas,
        &x_bytes,
        &mut rng,
    )
    .map_err(|e| TecdsaError::Other(format!("MPMtA2 x*gamma: {e}")))?;

    // --- Step 4: Build Round 2 message ---
    let mut mta_outputs = Vec::with_capacity(n);
    for j in 0..n {
        let kg_c_alpha_ser = SerializedClCt::from_bicycl_ct(&kg_mta.c_alphas[j])
            .map_err(|e| TecdsaError::Other(format!("serialize kg c_alpha[{j}]: {e}")))?;
        let xg_c_alpha_ser = SerializedClCt::from_bicycl_ct(&xg_mta.c_alphas[j])
            .map_err(|e| TecdsaError::Other(format!("serialize xg c_alpha[{j}]: {e}")))?;

        mta_outputs.push(R2PerPartyMtA {
            c_alpha: kg_c_alpha_ser,
            c_alpha_hat: xg_c_alpha_ser,
            b_point_bytes: kg_mta.beta_points[j].to_bytes().to_vec(),
            b_hat_point_bytes: xg_mta.beta_points[j].to_bytes().to_vec(),
        });
    }

    let pd_ser = SerializedQfi::from_qfi(&dec_dl_pd)
        .map_err(|e| TecdsaError::Other(format!("serialize pd: {e}")))?;

    let pd_c1_ser = SerializedQfi::from_qfi(&dec_dl_c1)
        .map_err(|e| TecdsaError::Other(format!("serialize pd_c1: {e}")))?;

    let dec_dl_proof_ser = SerRDecDlProof::from_proof(&dec_dl_proof)
        .map_err(|e| TecdsaError::Other(format!("serialize dec_dl_proof: {e}")))?;

    let kg_proof_ser = SerRMAffDlEcProof::from_proof(&kg_mta.proof)
        .map_err(|e| TecdsaError::Other(format!("serialize kg_proof: {e}")))?;

    let xg_proof_ser = SerRMAffDlEcProof::from_proof(&xg_mta.proof)
        .map_err(|e| TecdsaError::Other(format!("serialize xg_proof: {e}")))?;

    let r2_payload = R2Payload {
        mta_outputs,
        r_point_bytes: r_point_i.to_bytes().to_vec(),
        pd: pd_ser,
        pd_c1: pd_c1_ser,
        dec_dl_proof: dec_dl_proof_ser,
        kg_proof: kg_proof_ser,
        xg_proof: xg_proof_ser,
    };

    let payload_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R2 payload: {e}")))?;

    // Queue Round 2 broadcast.
    let mut outgoing = Vec::new();
    for &party in &state.all_parties {
        if party != state.my_id {
            outgoing.push(Outgoing {
                to: Recipient::Party(party),
                msg: Tx25PresignMsg::Round2(payload_bytes.clone()),
            });
        }
    }

    // Zeroize own PVSS share not carried to the next round
    state.own_pvss_share.zeroize();

    Ok(Round2State {
        my_id: state.my_id,
        all_parties: state.all_parties,
        gamma_i: state.gamma_i,
        k_i,
        all_c_gammas,
        kg_mta,
        xg_mta,
        received: BTreeMap::new(),
        outgoing,
    })
}

// ---------------------------------------------------------------------------
// Offline output computation (after Round 2)
// ---------------------------------------------------------------------------

/// Compute the presignature output from all collected Round 2 data.
///
/// 1. Verify R_Dec_DL proofs and R_m_AffDL_Ec proofs.
/// 2. Decrypt alpha values and compute delta/zeta shares.
/// 3. Reconstruct R via Lagrange interpolation.
/// 4. Produce the `Tx25Presignature`.
pub(crate) fn finalize(
    state: &Round2State,
    setup: &ClSetup,
    key_mat: &KeyMaterial,
) -> tecdsa_core::Result<Tx25Presignature> {
    let my_idx_val = my_idx(&state.all_parties, state.my_id)
        .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
    let n = state.all_parties.len();
    let party_ids_u16: Vec<u16> = state.all_parties.iter().map(|p| p.0).collect();
    let my_pid = state.my_id.0;

    // --- Step 1: Verify Round 2 proofs ---
    // Verify R_m_AffDL_Ec proofs for k*gamma and x*gamma MPMtA2.
    for (&party_j, r2) in &state.received {
        let j_idx = my_idx(&state.all_parties, party_j)
            .ok_or_else(|| TecdsaError::Other(format!("party {party_j} not found")))?;

        // Reconstruct MpmtaRound2Output for verification.
        let j_kg_r2 = MpmtaRound2Output {
            c_alphas: {
                let mut cas = Vec::with_capacity(n);
                for idx in 0..n {
                    let (c1, c2) = setup
                        .ct_components(&r2.kg_c_alphas[idx])
                        .map_err(|e| TecdsaError::Other(format!("ct_components: {e}")))?;
                    let ct = setup
                        .ct_from_components(&c1, &c2)
                        .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;
                    cas.push(ct);
                }
                cas
            },
            betas: vec![k256::Scalar::ZERO; n], // Unknown to verifier.
            beta_points: r2.b_points.clone(),
            k_star: Vec::new(), // Unknown to verifier (private).
            proof: {
                let (_d1, _) = setup
                    .ct_components(&r2.kg_c_alphas[0])
                    .map_err(|e| TecdsaError::Other(format!("components: {e}")))?;
                RMAffDlEcProof {
                    d_prime_1: {
                        let bytes = r2.kg_proof.d_prime_1.to_bytes();
                        Qfi::from_bytes(&bytes)
                    },
                    d_prime_2: {
                        let bytes = r2.kg_proof.d_prime_2.to_bytes();
                        Qfi::from_bytes(&bytes)
                    },
                    b0_bytes: r2.kg_proof.b0_bytes.clone(),
                    r0_bytes: r2.kg_proof.r0_bytes.clone(),
                    k_hat: r2.kg_proof.k_hat.clone(),
                    beta_hat: r2.kg_proof.beta_hat.clone(),
                    e: r2.kg_proof.e.clone(),
                }
            },
            r_point: r2.r_point,
        };

        // Verify k*gamma MPMtA2 proof.
        let kg_ok =
            mpmta_verify_round2(setup, &party_ids_u16, j_idx, &state.all_c_gammas, &j_kg_r2)
                .map_err(|e| {
                    TecdsaError::Other(format!("MPMtA2 k*gamma verify for party {party_j}: {e}"))
                })?;
        if !kg_ok {
            return Err(TecdsaError::Other(format!(
                "MPMtA2 k*gamma proof failed for party {party_j}"
            )));
        }

        // Verify x*gamma MPMtA2 proof (FAIL 3.8 fix).
        let j_xg_r2 = MpmtaRound2Output {
            c_alphas: {
                let mut cas = Vec::with_capacity(n);
                for idx in 0..n {
                    let (c1, c2) = setup
                        .ct_components(&r2.xg_c_alphas[idx])
                        .map_err(|e| TecdsaError::Other(format!("ct_components xg: {e}")))?;
                    let ct = setup
                        .ct_from_components(&c1, &c2)
                        .map_err(|e| TecdsaError::Other(format!("ct_from_components xg: {e}")))?;
                    cas.push(ct);
                }
                cas
            },
            betas: vec![k256::Scalar::ZERO; n],
            beta_points: r2.b_hat_points.clone(),
            k_star: Vec::new(),
            proof: {
                RMAffDlEcProof {
                    d_prime_1: {
                        let bytes = r2.xg_proof.d_prime_1.to_bytes();
                        Qfi::from_bytes(&bytes)
                    },
                    d_prime_2: {
                        let bytes = r2.xg_proof.d_prime_2.to_bytes();
                        Qfi::from_bytes(&bytes)
                    },
                    b0_bytes: r2.xg_proof.b0_bytes.clone(),
                    r0_bytes: r2.xg_proof.r0_bytes.clone(),
                    k_hat: r2.xg_proof.k_hat.clone(),
                    beta_hat: r2.xg_proof.beta_hat.clone(),
                    e: r2.xg_proof.e.clone(),
                }
            },
            // For x*gamma, r_point is x_j * G (the public share), not k_j * G.
            r_point: key_mat.public_shares[j_idx],
        };

        let xg_ok =
            mpmta_verify_round2(setup, &party_ids_u16, j_idx, &state.all_c_gammas, &j_xg_r2)
                .map_err(|e| {
                    TecdsaError::Other(format!("MPMtA2 x*gamma verify for party {party_j}: {e}"))
                })?;
        if !xg_ok {
            return Err(TecdsaError::Other(format!(
                "MPMtA2 x*gamma proof failed for party {party_j}"
            )));
        }

        // Verify R_Dec_DL proof (FAIL 3.6 fix).
        let pk_j = &key_mat.raw_pks[j_idx];
        // Build the ciphertext from pd_c1 (only c1 is used by verify).
        let dummy_c2 = setup
            .identity()
            .map_err(|e| TecdsaError::Other(format!("identity: {e}")))?;
        // Copy pd_c1 via binary round-trip since Qfi doesn't implement Clone.
        let c1_bytes = r2.pd_c1.to_bytes();
        let c1_copy = Qfi::from_bytes(&c1_bytes);
        let ct_for_verify = setup
            .ct_from_components(&c1_copy, &dummy_c2)
            .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;
        // Copy pd via binary round-trip.
        let pd_bytes = r2.pd.to_bytes();
        let pd_copy = Qfi::from_bytes(&pd_bytes);

        let dec_dl_ok = r2
            .dec_dl_proof
            .verify(setup, pk_j, &ct_for_verify, &pd_copy)
            .map_err(|e| TecdsaError::Other(format!("R_Dec_DL verify for party {party_j}: {e}")))?;
        if !dec_dl_ok {
            return Err(TecdsaError::Other(format!(
                "R_Dec_DL proof failed for party {party_j}"
            )));
        }
    }

    // --- Step 2: Decrypt alpha values and compute shares ---
    let sk_raw = setup
        .sk_from_bytes(&key_mat.sk_decimal)
        .map_err(|e| TecdsaError::Other(format!("sk_from_decimal: {e}")))?;

    let mut delta_shares: BTreeMap<u16, k256::Scalar> = BTreeMap::new();
    let mut zeta_shares: BTreeMap<u16, k256::Scalar> = BTreeMap::new();
    let mut b_points: BTreeMap<(u16, u16), k256::ProjectivePoint> = BTreeMap::new();
    let mut b_hat_points: BTreeMap<(u16, u16), k256::ProjectivePoint> = BTreeMap::new();

    // Collect R points for Lagrange interpolation.
    let mut r_points: BTreeMap<u16, k256::ProjectivePoint> = BTreeMap::new();
    r_points.insert(my_pid, state.kg_mta.r_point);

    // Store our own beta points.
    for (j, &party_j) in state.all_parties.iter().enumerate() {
        let j_pid = party_j.0;
        b_points.insert((my_pid, j_pid), state.kg_mta.beta_points[j]);
        b_hat_points.insert((my_pid, j_pid), state.xg_mta.beta_points[j]);
    }

    // Process each other party's Round 2 data.
    for (&party_j, r2) in &state.received {
        let j_pid = party_j.0;
        let j_idx = my_idx(&state.all_parties, party_j)
            .ok_or_else(|| TecdsaError::Other(format!("party {party_j} not found")))?;

        r_points.insert(j_pid, r2.r_point);

        // Store party j's beta points for all counterparties.
        for (nu_idx, &party_nu) in state.all_parties.iter().enumerate() {
            let nu_pid = party_nu.0;
            b_points.insert((j_pid, nu_pid), r2.b_points[nu_idx]);
            b_hat_points.insert((j_pid, nu_pid), r2.b_hat_points[nu_idx]);
        }

        // Decrypt alpha_{i,j} from party j's C_alpha (k*gamma MtA).
        let c_alpha_ij = &r2.kg_c_alphas[my_idx_val];
        let alpha_kg_bytes = setup.decrypt_bytes(&sk_raw, c_alpha_ij).map_err(|e| {
            TecdsaError::Other(format!("decrypt k*gamma alpha from party {party_j}: {e}"))
        })?;
        let alpha_kg = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_kg_bytes);

        // Our beta for party j (from our MPMtA2 output for k*gamma).
        let beta_kg_ij = state.kg_mta.betas[j_idx];

        // delta_{i,j} = alpha_{i,j} + beta_{i,j}
        delta_shares.insert(j_pid, alpha_kg + beta_kg_ij);

        // Same for x*gamma MtA.
        let c_alpha_hat_ij = &r2.xg_c_alphas[my_idx_val];
        let alpha_xg_bytes = setup.decrypt_bytes(&sk_raw, c_alpha_hat_ij).map_err(|e| {
            TecdsaError::Other(format!("decrypt x*gamma alpha from party {party_j}: {e}"))
        })?;
        let alpha_xg = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_xg_bytes);

        let beta_xg_ij = state.xg_mta.betas[j_idx];
        zeta_shares.insert(j_pid, alpha_xg + beta_xg_ij);
    }

    // Self-entries: delta_{i,i} = k_i * gamma_i (diagonal product).
    delta_shares.insert(my_pid, state.k_i * state.gamma_i);
    // zeta_{i,i} = x_i * gamma_i.
    zeta_shares.insert(my_pid, key_mat.x_i * state.gamma_i);

    // --- Step 3: Compute R = sum lambda_{j,S} * R_j ---
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_u16);

    let mut r_combined = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (idx, &party_j) in state.all_parties.iter().enumerate() {
        let j_pid = party_j.0;
        let r_j = r_points
            .get(&j_pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R point for party {j_pid}")))?;
        r_combined += *r_j * lagrange_coeffs[idx];
    }

    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_combined.to_affine());

    // --- Step 4: Compute sigma_share ---
    let sigma_share: k256::Scalar = zeta_shares.values().copied().sum();

    Ok(Tx25Presignature {
        r_point: r_combined,
        r_x,
        k_share: state.k_i,
        gamma_i: state.gamma_i,
        sigma_share,
        delta_shares,
        zeta_shares,
        b_points,
        b_hat_points,
        party_index: my_pid,
        threshold: key_mat.threshold,
    })
}
