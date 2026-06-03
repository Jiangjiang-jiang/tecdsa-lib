// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 keygen round state structs and transition logic.

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use tecdsa_class_group::{
    cl::{ClPublicKey, ClSecretKey, ClSetup, Qfi},
    zk::r_dec_dl::RDecDlProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, PartyId, Recipient};

use super::{abc_to_qfi, msg::Tx25KeygenMsg, qfi_to_abc, serialize_round2, serialize_round3};
use crate::{
    key_share::Tx25KeyShare,
    pvss::{pvss_decrypt_share, pvss_distribute, PvssOutput},
};

// ---------------------------------------------------------------------------
// Internal round states
// ---------------------------------------------------------------------------

/// Round 1 state: after generating CL keypair and queuing broadcast.
pub(crate) struct Round1State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) threshold: u16,
    pub(crate) cl_sk_raw: ClSecretKey,
    pub(crate) cl_pk_raw: ClPublicKey,
    pub(crate) cl_sk_decimal: Vec<u8>,
    pub(crate) cl_pk_abc: (String, String, String),
    pub(crate) received: BTreeMap<PartyId, Round1Msg>,
    pub(crate) outgoing: Vec<Outgoing<Tx25KeygenMsg>>,
    pub(crate) cl_setup_seed: String,
    pub(crate) use_128bit_security: bool,
}

/// Deserialized Round 1 message from a peer.
pub(crate) struct Round1Msg {
    pub(crate) cl_pk_abc: (String, String, String),
}

/// Round 2 state: after distributing PVSS shares.
pub(crate) struct Round2State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) threshold: u16,
    pub(crate) cl_sk_raw: ClSecretKey,
    pub(crate) cl_pk_raw: ClPublicKey,
    pub(crate) cl_sk_decimal: Vec<u8>,
    /// All parties' PK abcs in party order (including self).
    pub(crate) cl_pk_abcs: BTreeMap<PartyId, (String, String, String)>,
    pub(crate) my_pvss: PvssOutput,
    pub(crate) received: BTreeMap<PartyId, Round2Msg>,
    pub(crate) outgoing: Vec<Outgoing<Tx25KeygenMsg>>,
    pub(crate) cl_setup_seed: String,
    pub(crate) use_128bit_security: bool,
}

/// Deserialized Round 2 message from a peer.
pub(crate) struct Round2Msg {
    pub(crate) c1: Qfi,
    pub(crate) c2s: Vec<Qfi>,
}

/// Round 3 state: after decrypting and combining shares.
pub(crate) struct Round3State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) threshold: u16,
    pub(crate) secret_share: k256::Scalar,
    pub(crate) my_public_share: k256::ProjectivePoint,
    pub(crate) received: BTreeMap<PartyId, Round3Msg>,
    pub(crate) outgoing: Vec<Outgoing<Tx25KeygenMsg>>,
    pub(crate) cl_setup_seed: String,
    pub(crate) use_128bit_security: bool,
    pub(crate) cl_sk: ClSecretKey,
    pub(crate) cl_pks: Vec<ClPublicKey>,
    /// Per-party PVSS c1 values from Round 2 (needed for R_Dec_DL verification).
    pub(crate) pvss_c1_abcs: BTreeMap<PartyId, (String, String, String)>,
    /// Per-party CL public key abcs (needed for R_Dec_DL verification).
    pub(crate) cl_pk_abcs: BTreeMap<PartyId, (String, String, String)>,
}

/// Deserialized Round 3 message from a peer.
pub(crate) struct Round3Msg {
    pub(crate) public_share: k256::ProjectivePoint,
}

/// Internal round enum for the keygen state machine.
pub(crate) enum KeygenRound {
    Round1(Round1State),
    Round2(Round2State),
    Round3(Round3State),
    Done(Tx25KeyShare),
    Poisoned,
}

// ---------------------------------------------------------------------------
// Round transitions
// ---------------------------------------------------------------------------

/// Transition from Round 1 to Round 2.
///
/// Collects all verified CL public keys, runs PVSS ShareDist, serializes
/// the output, and queues Round 2 broadcasts.
pub(crate) fn transition_r1_to_r2(
    setup: &mut ClSetup,
    state: Round1State,
) -> tecdsa_core::Result<Round2State> {
    let n = state.all_parties.len();
    let my_id = state.my_id;
    let my_idx = state
        .all_parties
        .iter()
        .position(|p| *p == my_id)
        .expect("my_id must be in all_parties");

    // Collect all CL public keys and abcs in party order.
    let mut cl_pk_abcs: BTreeMap<PartyId, (String, String, String)> = BTreeMap::new();
    let mut ordered_pks: Vec<ClPublicKey> = Vec::with_capacity(n);

    for pid in &state.all_parties {
        if *pid == my_id {
            // Clone our own PK from QFI.
            let pk_elt = state.cl_pk_raw.elt();
            let pk_clone = setup
                .pk_from_qfi(pk_elt)
                .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
            ordered_pks.push(pk_clone);
            cl_pk_abcs.insert(*pid, state.cl_pk_abc.clone());
        } else {
            let r1_msg = state.received.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing R1 message from party {pid}"))
            })?;
            // Clone the peer's PK by re-reconstructing from abc.
            let qfi = abc_to_qfi(&r1_msg.cl_pk_abc)
                .map_err(|e| TecdsaError::Other(format!("abc_to_qfi: {e}")))?;
            let pk = setup
                .pk_from_qfi(&qfi)
                .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
            ordered_pks.push(pk);
            cl_pk_abcs.insert(*pid, r1_msg.cl_pk_abc.clone());
        }
    }

    // Run PVSS ShareDist.
    let party_ids: Vec<u16> = (1..=n as u16).collect();
    let mut rng = rand::thread_rng();

    let pvss_output = pvss_distribute(
        setup,
        &party_ids,
        &ordered_pks,
        state.threshold,
        my_idx,
        &mut rng,
    )
    .map_err(|e| TecdsaError::Other(format!("pvss_distribute failed: {e}")))?;

    // Serialize Round 2 message.
    let r2_payload = serialize_round2(&pvss_output)
        .map_err(|e| TecdsaError::Other(format!("R2 serialize failed: {e}")))?;

    // Queue broadcast to all other parties.
    let mut outgoing = Vec::new();
    for party in &state.all_parties {
        if *party != my_id {
            outgoing.push(Outgoing {
                to: Recipient::Party(*party),
                msg: Tx25KeygenMsg::Round2(r2_payload.clone()),
            });
        }
    }

    // Clone the PK raw for Round 2 state.
    let my_pk_elt = state.cl_pk_raw.elt();
    let my_pk_clone = setup
        .pk_from_qfi(my_pk_elt)
        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

    Ok(Round2State {
        my_id,
        all_parties: state.all_parties,
        threshold: state.threshold,
        cl_sk_raw: state.cl_sk_raw,
        cl_pk_raw: my_pk_clone,
        cl_sk_decimal: state.cl_sk_decimal,
        cl_pk_abcs,
        my_pvss: pvss_output,
        received: BTreeMap::new(),
        outgoing,
        cl_setup_seed: state.cl_setup_seed,
        use_128bit_security: state.use_128bit_security,
    })
}

/// Transition from Round 2 to Round 3.
///
/// For each received PVSS distribution, decrypts this party's encrypted
/// share.  Combines all shares into a single secret share x_i, computes
/// X_i = x_i * G, generates an R_Dec_DL proof, and queues Round 3
/// broadcasts.
pub(crate) fn transition_r2_to_r3(
    setup: &mut ClSetup,
    state: Round2State,
) -> tecdsa_core::Result<Round3State> {
    let n = state.all_parties.len();
    let my_id = state.my_id;
    let my_idx = state
        .all_parties
        .iter()
        .position(|p| *p == my_id)
        .expect("my_id must be in all_parties");

    // Start with our own PVSS share (the share from our own polynomial).
    let mut x_i = state.my_pvss.secret_share;

    // For each other party's PVSS distribution, decrypt our share and add.
    for pid in &state.all_parties {
        if *pid == my_id {
            continue;
        }
        let r2_msg = state
            .received
            .get(pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing R2 message from party {pid}")))?;

        // Decrypt: x_{i,j} = Dec(dk_i, (c1, c2[my_idx])).
        let share_j = pvss_decrypt_share(setup, &state.cl_sk_raw, &r2_msg.c1, &r2_msg.c2s[my_idx])
            .map_err(|e| TecdsaError::Other(format!("pvss_decrypt_share from {pid}: {e}")))?;

        // Combine: x_i += x_{i,j} mod q.
        x_i += share_j;
    }

    // Compute X_i = x_i * G.
    let big_x_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x_i;
    let big_x_i_bytes = big_x_i.to_bytes().to_vec();

    // Generate R_Dec_DL proof.
    // Build a ciphertext from (c1, c2_my) of our own PVSS output.
    let c1_ref = &state.my_pvss.c1;
    let c2_my_ref = &state.my_pvss.c2s[my_idx];
    let ct_ref = setup
        .ct_from_components(c1_ref, c2_my_ref)
        .map_err(|e| TecdsaError::Other(format!("ct_from_components: {e}")))?;

    // Partial decryption: pd = c1^{sk}.
    let pd = setup
        .exp_bytes(c1_ref, &state.cl_sk_decimal)
        .map_err(|e| TecdsaError::Other(format!("exp for pd: {e}")))?;

    let r_dec_dl_proof =
        RDecDlProof::prove(setup, &state.cl_pk_raw, &ct_ref, &pd, &state.cl_sk_decimal)
            .map_err(|e| TecdsaError::Other(format!("R_Dec_DL prove failed: {e}")))?;

    // Serialize Round 3 message (includes pd for R_Dec_DL verification).
    let r3_payload = serialize_round3(&big_x_i_bytes, &pd, &r_dec_dl_proof)
        .map_err(|e| TecdsaError::Other(format!("R3 serialize failed: {e}")))?;

    // Queue broadcast.
    let mut outgoing = Vec::new();
    for party in &state.all_parties {
        if *party != my_id {
            outgoing.push(Outgoing {
                to: Recipient::Party(*party),
                msg: Tx25KeygenMsg::Round3(r3_payload.clone()),
            });
        }
    }

    // Build CL key types for the key share output.
    let cl_sk = setup
        .sk_from_bytes(&state.cl_sk_decimal)
        .map_err(|e| TecdsaError::Other(format!("sk_from_decimal: {e}")))?;

    // Reconstruct all CL public keys from stored abcs.
    let mut cl_pks: Vec<ClPublicKey> = Vec::with_capacity(n);
    for pid in &state.all_parties {
        let abc = state
            .cl_pk_abcs
            .get(pid)
            .ok_or_else(|| TecdsaError::Other(format!("missing pk abc for party {pid}")))?;
        let qfi =
            abc_to_qfi(abc).map_err(|e| TecdsaError::Other(format!("abc_to_qfi: {e}")))?;
        let pk_raw = setup
            .pk_from_qfi(&qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;
        cl_pks.push(pk_raw);
    }

    // Carry forward per-party PVSS c1 values (as abc strings) for
    // R_Dec_DL verification in Round 3.
    let mut pvss_c1_abcs: BTreeMap<PartyId, (String, String, String)> = BTreeMap::new();
    // Our own PVSS c1.
    let own_c1_abc = qfi_to_abc(&state.my_pvss.c1)
        .map_err(|e| TecdsaError::Other(format!("qfi_to_abc own c1: {e}")))?;
    pvss_c1_abcs.insert(my_id, own_c1_abc);
    // Other parties' PVSS c1 values.
    for (pid, r2_msg) in &state.received {
        let c1_abc = qfi_to_abc(&r2_msg.c1)
            .map_err(|e| TecdsaError::Other(format!("qfi_to_abc c1 from {pid}: {e}")))?;
        pvss_c1_abcs.insert(*pid, c1_abc);
    }

    Ok(Round3State {
        my_id,
        all_parties: state.all_parties,
        threshold: state.threshold,
        secret_share: x_i,
        my_public_share: big_x_i,
        received: BTreeMap::new(),
        outgoing,
        cl_setup_seed: state.cl_setup_seed,
        use_128bit_security: state.use_128bit_security,
        cl_sk,
        cl_pks,
        pvss_c1_abcs,
        cl_pk_abcs: state.cl_pk_abcs,
    })
}

/// Finalize keygen: collect all public shares and compute the joint
/// public key using Lagrange interpolation.
pub(crate) fn finalize_keygen(state: Round3State) -> tecdsa_core::Result<Tx25KeyShare> {
    let n = state.all_parties.len();
    let my_id = state.my_id;
    let my_idx = state
        .all_parties
        .iter()
        .position(|p| *p == my_id)
        .expect("my_id must be in all_parties");

    // Collect all public shares in party order.
    let mut public_shares: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);
    for pid in &state.all_parties {
        if *pid == my_id {
            public_shares.push(state.my_public_share);
        } else {
            let r3_msg = state.received.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing R3 message from party {pid}"))
            })?;
            public_shares.push(r3_msg.public_share);
        }
    }

    // Compute joint public key X = sum_{j in S} lambda_{j,S} * X_j.
    // The party indices for Lagrange interpolation are 1-based.
    let indices: Vec<u16> = (1..=n as u16).collect();
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);

    let public_key = public_shares.iter().zip(lagrange_coeffs.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (x_j, lambda_j)| acc + *x_j * lambda_j,
    );

    let party_index = (my_idx + 1) as u16; // 1-based

    Ok(Tx25KeyShare {
        party_index,
        secret_share: state.secret_share,
        public_key,
        public_shares,
        cl_sk: state.cl_sk,
        cl_pks: state.cl_pks,
        cl_setup_seed: state.cl_setup_seed,
        use_128bit_security: state.use_128bit_security,
        threshold: state.threshold,
        total: n as u16,
    })
}
