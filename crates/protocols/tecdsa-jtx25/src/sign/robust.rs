// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    non_snake_case
)]

//! JTX25 online signing protocol (1 round).
//!
//! Consumes a [`Jtx25RobustPresignature`] and a message to produce a threshold
//! ECDSA signature via threshold CL partial decryption.
//!
//! ## Protocol (JTX25 Section 4, Online Round 3)
//!
//! Each party P_i:
//! 1. Compute c^0 = sum_{j in T} (phi_bar_k_j * lambda_j) = Enc(pk, phi*k)
//! 2. Compute c^1 = (phi_bar * H(m)) + sum_{j in T} (phi_bar_x_j * (lambda_j * r_x))
//!    = Enc(pk, phi*(H(m) + x*r_x))
//! 3. Partial decrypt: (pc_i^0, pi_0) <- t-CL.PartDec(pk, sk_i, c^0)
//! 4. Partial decrypt: (pc_i^1, pi_1) <- t-CL.PartDec(pk, sk_i, c^1)
//! 5. Broadcast (pc_i^0, pi_0, pc_i^1, pi_1)
//!
//! ## Output
//! 1. Verify all R_part-dec proofs
//! 2. p^0 <- t-CL.FinDec(pk, {pc_i^0}, c^0)
//! 3. p^1 <- t-CL.FinDec(pk, {pc_i^1}, c^1)
//! 4. s = p^1 / p^0 mod q
//! 5. Verify(m; (r_x, s)): if valid, output (r_x, s)

use std::collections::BTreeMap;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClPublicKey, ClSetup, Qfi},
    t_cl::{final_decrypt as threshold_cl_combine, PartialDecryption as ClPartialDecryption},
    zk::r_part_dec::RPartDecProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
    state_machine::Outgoing,
    IaReport, PartyId, Recipient, StateMachine,
};

use crate::{
    cl_wire::{SerRPartDecProof, SerializedQfi},
    presign::robust::Jtx25RobustPresignature,
};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Jtx25RobustOnlineSignMsg {
    Round3(Vec<u8>),
}

// Serialized types imported from crate::cl_wire

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R3Payload {
    /// Partial decryption of c^0.
    pc_0: SerializedQfi,
    /// R_part_dec proof for c^0.
    pi_0: SerRPartDecProof,
    /// Partial decryption of c^1.
    pc_1: SerializedQfi,
    /// R_part_dec proof for c^1.
    pi_1: SerRPartDecProof,
    /// Party index (1-based) for t-CL.FinDec.
    party_index: usize,
}

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

struct ReceivedR3 {
    pc_0: Qfi,
    pc_1: Qfi,
    party_index: usize,
}

// ---------------------------------------------------------------------------
// Message hashing
// ---------------------------------------------------------------------------

fn hash_message_to_scalar(message: &[u8]) -> k256::Scalar {
    let hash: [u8; 32] = Sha256::digest(message).into();
    tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&hash)
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

pub struct Jtx25RobustOnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    presignature: Jtx25RobustPresignature,
    _message_hash: k256::Scalar,
    message: DataToSign<k256::Secp256k1>,
    public_key: k256::ProjectivePoint,
    /// The c^0 and c^1 ciphertexts (computed locally, same for all parties).
    c0: ClCiphertext,
    c1: ClCiphertext,
    /// CL setup.
    setup: ClSetup,
    /// Aggregate CL PK (for verification).
    _cl_pk: ClPublicKey,
    /// Per-party CL PK shares (for verifying partial decryption proofs).
    cl_pk_shares: BTreeMap<u16, ClPublicKey>,
    /// Received Round 3 messages.
    received: BTreeMap<u16, ReceivedR3>,
    outgoing: Vec<Outgoing<Jtx25RobustOnlineSignMsg>>,
    output: Option<Signature<k256::Secp256k1>>,
    ia_report: Option<IaReport>,
    done: bool,
}

impl Jtx25RobustOnlineSignMachine {
    /// Create a new JTX25 online signing state machine.
    ///
    /// Computes c^0 and c^1 from the presignature, then performs partial
    /// decryption and queues the broadcast.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Jtx25RobustPresignature,
        message: &[u8],
        public_key: k256::ProjectivePoint,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }

        let m = hash_message_to_scalar(message);
        let m_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&m);
        let message_data = DataToSign::from_digest(m);
        let r_x = presignature.r_x;
        let r_x_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&r_x);

        // Create CL setup.
        let mut setup = if presignature.use_128bit_security {
            ClSetup::new_secp256k1_128bit(&presignature.cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(&presignature.cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup: {e}")))?;

        // Reconstruct phi_bar ciphertext.
        let pb_c1 = Qfi::from_bytes(&presignature.phi_bar_c1_bytes);
        let pb_c2 = Qfi::from_bytes(&presignature.phi_bar_c2_bytes);
        let phi_bar = setup
            .ct_from_components(&pb_c1, &pb_c2)
            .map_err(|e| TecdsaError::Other(format!("phi_bar ct: {e}")))?;

        // Reconstruct aggregate CL PK.
        let cl_pk_qfi = Qfi::from_bytes(&presignature.cl_pk_bytes);
        let cl_pk = setup
            .pk_from_qfi(&cl_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("cl_pk from_qfi: {e}")))?;

        // Reconstruct per-party CL PK shares (1-based keys matching PartyId.0).
        let mut cl_pk_shares: BTreeMap<u16, ClPublicKey> = BTreeMap::new();
        for (&pid, bytes) in &presignature.cl_pk_share_bytes {
            let qfi = Qfi::from_bytes(bytes);
            let pk = setup
                .pk_from_qfi(&qfi)
                .map_err(|e| TecdsaError::Other(format!("pk_from_qfi {pid}: {e}")))?;
            cl_pk_shares.insert(pid, pk);
        }

        // --- Compute c^0 = sum_{j in T} (phi_bar_k_j * lambda_j) ---
        // This is the homomorphic sum of component-wise scalar multiples.
        let party_ids: Vec<u16> = all_parties.iter().map(|p| p.0).collect();
        let mut c0_opt: Option<ClCiphertext> = None;

        for &pid in &party_ids {
            let lambda_j = presignature
                .lagrange_coeffs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing lagrange coeff for {pid}")))?;
            let lambda_j_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(lambda_j);

            let kc1_bytes = presignature
                .phi_bar_k_c1_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_k c1 for {pid}")))?;
            let kc2_bytes = presignature
                .phi_bar_k_c2_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_k c2 for {pid}")))?;

            let kc1 = Qfi::from_bytes(kc1_bytes);
            let kc2 = Qfi::from_bytes(kc2_bytes);
            let phi_bar_k_j = setup
                .ct_from_components(&kc1, &kc2)
                .map_err(|e| TecdsaError::Other(format!("phi_bar_k ct: {e}")))?;

            // Scalar multiply by lambda_j: component-wise.
            let (pk1, pk2) = setup
                .ct_components(&phi_bar_k_j)
                .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
            let pk1_l = setup
                .exp_bytes(&pk1, &lambda_j_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
            let pk2_l = setup
                .exp_bytes(&pk2, &lambda_j_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
            let term = setup
                .ct_from_components(&pk1_l, &pk2_l)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

            c0_opt = Some(match c0_opt.take() {
                None => term,
                Some(acc) => {
                    let (a1, a2) = setup
                        .ct_components(&acc)
                        .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
                    let (b1, b2) = setup
                        .ct_components(&term)
                        .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
                    let s1 = setup
                        .compose(&a1, &b1)
                        .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
                    let s2 = setup
                        .compose(&a2, &b2)
                        .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
                    setup
                        .ct_from_components(&s1, &s2)
                        .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?
                }
            });
        }
        let c0 = c0_opt.ok_or_else(|| TecdsaError::Other("no c0 data".into()))?;

        // --- Compute c^1 = (phi_bar * H(m)) + sum_{j in T} (phi_bar_x_j * (lambda_j * r_x)) ---
        // First term: phi_bar * H(m) = component-wise exponentiation.
        let (phb_c1, phb_c2) = setup
            .ct_components(&phi_bar)
            .map_err(|e| TecdsaError::Other(format!("phi_bar comp: {e}")))?;
        let phb_c1_m = setup
            .exp_bytes(&phb_c1, &m_bytes)
            .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
        let phb_c2_m = setup
            .exp_bytes(&phb_c2, &m_bytes)
            .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
        let phi_bar_m = setup
            .ct_from_components(&phb_c1_m, &phb_c2_m)
            .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

        let mut c1_ct = phi_bar_m;

        // Sum term: sum_{j in T} (phi_bar_x_j * (lambda_j * r_x))
        for &pid in &party_ids {
            let _lambda_j = presignature
                .lagrange_coeffs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing lagrange coeff for {pid}")))?;
            // Note: In the paper, the Lagrange coefficient is already applied during
            // presign (phi_bar_x_i = phi_bar * (lambda_i * x_i)). So here we only
            // multiply by r_x (not lambda_j * r_x) since the lambda is already baked in.
            // Actually re-reading the protocol spec: the lambda_j are re-applied during
            // online sign because the signing set may differ from the presign set.
            // But in our implementation the presign already uses the same party set,
            // and each party computed phi_bar_x_i = phi_bar * (lambda_i * x_i).
            // So we just need to add them without additional lambda weighting,
            // but DO need to multiply each by r_x.

            let xc1_bytes = presignature
                .phi_bar_x_c1_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_x c1 for {pid}")))?;
            let xc2_bytes = presignature
                .phi_bar_x_c2_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_x c2 for {pid}")))?;

            let xc1 = Qfi::from_bytes(xc1_bytes);
            let xc2 = Qfi::from_bytes(xc2_bytes);
            let phi_bar_x_j = setup
                .ct_from_components(&xc1, &xc2)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

            // Multiply by r_x.
            let (px1, px2) = setup
                .ct_components(&phi_bar_x_j)
                .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
            let px1_r = setup
                .exp_bytes(&px1, &r_x_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
            let px2_r = setup
                .exp_bytes(&px2, &r_x_bytes)
                .map_err(|e| TecdsaError::Other(format!("exp: {e}")))?;
            let term = setup
                .ct_from_components(&px1_r, &px2_r)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

            // Add to c1.
            let (a1, a2) = setup
                .ct_components(&c1_ct)
                .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
            let (b1, b2) = setup
                .ct_components(&term)
                .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
            let s1 = setup
                .compose(&a1, &b1)
                .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
            let s2 = setup
                .compose(&a2, &b2)
                .map_err(|e| TecdsaError::Other(format!("compose: {e}")))?;
            c1_ct = setup
                .ct_from_components(&s1, &s2)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;
        }

        // --- Partial decryption ---
        // party_index for t-CL partial decryption is 1-based (matching
        // the Shamir evaluation points in shamir_share_delta).
        // presignature.party_index is PartyId.0 (already 1-based).
        let my_party_index = presignature.party_index as usize;
        let sk_share = &presignature.cl_sk_share;

        // Build PK share for proof.
        let my_pk_data = presignature
            .cl_pk_share_bytes
            .get(&presignature.party_index)
            .ok_or_else(|| TecdsaError::Other("missing own CL pk share".into()))?;
        let my_pk_qfi = Qfi::from_bytes(my_pk_data);
        let my_pk_raw = setup
            .pk_from_qfi(&my_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        // Partial decrypt c^0.
        let (c0_c1, _) = setup
            .ct_components(&c0)
            .map_err(|e| TecdsaError::Other(format!("c0 comp: {e}")))?;
        let pc_0 = setup
            .exp_bytes(&c0_c1, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pc_0: {e}")))?;
        let pi_0 = RPartDecProof::prove(&mut setup, &my_pk_raw, &c0, &pc_0, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pi_0: {e}")))?;

        // Partial decrypt c^1.
        let (c1_c1_comp, _) = setup
            .ct_components(&c1_ct)
            .map_err(|e| TecdsaError::Other(format!("c1 comp: {e}")))?;
        let pc_1 = setup
            .exp_bytes(&c1_c1_comp, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pc_1: {e}")))?;
        let pi_1 = RPartDecProof::prove(&mut setup, &my_pk_raw, &c1_ct, &pc_1, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pi_1: {e}")))?;

        // Serialize and broadcast.
        let pc_0_ser = SerializedQfi::from_qfi(&pc_0)
            .map_err(|e| TecdsaError::Other(format!("ser pc_0: {e}")))?;
        let pi_0_ser = SerRPartDecProof::from_proof(&pi_0)
            .map_err(|e| TecdsaError::Other(format!("ser pi_0: {e}")))?;
        let pc_1_ser = SerializedQfi::from_qfi(&pc_1)
            .map_err(|e| TecdsaError::Other(format!("ser pc_1: {e}")))?;
        let pi_1_ser = SerRPartDecProof::from_proof(&pi_1)
            .map_err(|e| TecdsaError::Other(format!("ser pi_1: {e}")))?;

        let r3_payload = R3Payload {
            pc_0: pc_0_ser,
            pi_0: pi_0_ser,
            pc_1: pc_1_ser,
            pi_1: pi_1_ser,
            party_index: my_party_index,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R3: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25RobustOnlineSignMsg::Round3(payload_bytes),
        }];

        // Store own partial decryptions.
        let mut received = BTreeMap::new();
        received.insert(
            presignature.party_index,
            ReceivedR3 {
                pc_0,
                pc_1,
                party_index: my_party_index,
            },
        );

        Ok(Self {
            my_id,
            all_parties,
            presignature,
            _message_hash: m,
            message: message_data,
            public_key,
            c0,
            c1: c1_ct,
            setup,
            _cl_pk: cl_pk,
            cl_pk_shares,
            received,
            outgoing,
            output: None,
            ia_report: None,
            done: false,
        })
    }

    fn all_collected(&self) -> bool {
        self.received.len() == self.all_parties.len()
    }

    /// Assemble the final signature from partial decryptions.
    fn try_finalize(&mut self) -> tecdsa_core::Result<()> {
        let n_parties_dkg = self.presignature.n_parties_dkg;
        let r_x = self.presignature.r_x;

        // Collect partial decryptions for c^0 and c^1.
        let mut pd_0s: Vec<ClPartialDecryption> = Vec::new();
        let mut pd_1s: Vec<ClPartialDecryption> = Vec::new();

        for r3 in self.received.values() {
            // Copy the QFI via binary round-trip since we need to move into PartialDecryption.
            let pc0_bytes = r3.pc_0.to_bytes();
            let pc0_copy = Qfi::from_bytes(&pc0_bytes);

            let pc1_bytes = r3.pc_1.to_bytes();
            let pc1_copy = Qfi::from_bytes(&pc1_bytes);

            pd_0s.push(ClPartialDecryption {
                party_index: r3.party_index,
                dec_share: pc0_copy,
            });
            pd_1s.push(ClPartialDecryption {
                party_index: r3.party_index,
                dec_share: pc1_copy,
            });
        }

        // Final decrypt c^0.
        let p0_bytes = threshold_cl_combine(&self.setup, &self.c0, n_parties_dkg, &pd_0s)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt c0: {e}")))?;

        // Final decrypt c^1.
        let p1_bytes = threshold_cl_combine(&self.setup, &self.c1, n_parties_dkg, &pd_1s)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt c1: {e}")))?;

        // s = p^1 / p^0 mod q
        let q_bytes = self
            .setup
            .q_bytes()
            .map_err(|e| TecdsaError::Other(format!("q_bytes: {e}")))?;
        let q = BigUint::from_bytes_be(&q_bytes);

        let p0 = BigUint::from_bytes_be(&p0_bytes);
        let p1 = BigUint::from_bytes_be(&p1_bytes);

        // p0_inv = p0^{q-2} mod q (Fermat's little theorem).
        let q_minus_2 = &q - BigUint::from(2u32);
        let p0_inv = p0.modpow(&q_minus_2, &q);

        let s_big = (&p1 * &p0_inv) % &q;
        let s_raw = tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&s_big);
        let s = low_s_normalize::<k256::Secp256k1>(s_raw);

        let sig = Signature { r: r_x, s };

        // Verify the signature.
        if verify_ecdsa::<k256::Secp256k1>(&sig, &self.public_key, &self.message).is_ok() {
            self.output = Some(sig);
            self.done = true;
            return Ok(());
        }

        // Also try with negated s.
        let s_neg = low_s_normalize::<k256::Secp256k1>(-s_raw);
        let sig_neg = Signature { r: r_x, s: s_neg };
        if verify_ecdsa::<k256::Secp256k1>(&sig_neg, &self.public_key, &self.message).is_ok() {
            self.output = Some(sig_neg);
            self.done = true;
            return Ok(());
        }

        self.done = true;
        Err(TecdsaError::Other(
            "ECDSA verification failed after signature assembly".into(),
        ))
    }
}

impl StateMachine for Jtx25RobustOnlineSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Jtx25RobustOnlineSignMsg;
    type Outbound = Jtx25RobustOnlineSignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if self.done {
            return Err(TecdsaError::Other("machine already done".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        let from_pid = from.0;
        if self.received.contains_key(&from_pid) {
            return Err(TecdsaError::Other(format!("duplicate from {from}")));
        }

        match msg {
            Jtx25RobustOnlineSignMsg::Round3(data) => {
                let (payload, _): (R3Payload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R3: {e}")))?;

                let pc_0 = payload
                    .pc_0
                    .to_qfi()
                    .map_err(|e| TecdsaError::Other(format!("pc_0 from {from}: {e}")))?;
                let pi_0 = payload
                    .pi_0
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("pi_0 from {from}: {e}")))?;
                let pc_1 = payload
                    .pc_1
                    .to_qfi()
                    .map_err(|e| TecdsaError::Other(format!("pc_1 from {from}: {e}")))?;
                let pi_1 = payload
                    .pi_1
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("pi_1 from {from}: {e}")))?;

                // Verify R_part_dec proofs.
                let from_pk = self
                    .cl_pk_shares
                    .get(&from_pid)
                    .ok_or_else(|| TecdsaError::Other(format!("missing CL pk share for {from}")))?;

                let pi_0_ok = pi_0
                    .verify(&self.setup, from_pk, &self.c0, &pc_0)
                    .map_err(|e| TecdsaError::Other(format!("pi_0 verify from {from}: {e}")))?;
                let pi_1_ok = pi_1
                    .verify(&self.setup, from_pk, &self.c1, &pc_1)
                    .map_err(|e| TecdsaError::Other(format!("pi_1 verify from {from}: {e}")))?;

                // Both proofs must pass (AND).
                if !pi_0_ok || !pi_1_ok {
                    return Err(TecdsaError::Other(format!(
                        "R_part_dec proof failed for {from}: pi_0={pi_0_ok}, pi_1={pi_1_ok}"
                    )));
                }

                // Convert the party_index: if the sender sends their 1-based
                // index directly, use it. Otherwise convert from PartyId.
                // The payload.party_index is set by the sender as
                // presignature.party_index + 1 (1-based).
                self.received.insert(
                    from_pid,
                    ReceivedR3 {
                        pc_0,
                        pc_1,
                        party_index: payload.party_index,
                    },
                );

                if self.all_collected() {
                    self.try_finalize()?;
                }
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .ok_or_else(|| TecdsaError::Other("online sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            4
        } else {
            3
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
