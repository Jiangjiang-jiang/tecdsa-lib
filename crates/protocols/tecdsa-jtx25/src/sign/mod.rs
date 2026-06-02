// SPDX-License-Identifier: GPL-3.0-or-later
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

//! JTX25 TECDSA-Normal online signing protocol (1 round).
//!
//! Consumes a [`Jtx25Presignature`] and a message to produce a threshold
//! ECDSA signature via threshold CL partial decryption.
//!
//! ## Key difference from TECDSA-Robust
//!
//! Since k = sum(k_i) is additively shared (n-out-of-n), the ciphertext
//! c^0 = sum(phi_bar_k_j) needs NO Lagrange weighting. The Robust variant
//! uses c^0 = sum(phi_bar_k_j * lambda_j) because k is threshold-shared.
//!
//! ## Protocol (JTX25 Section 3, Figure 4, Online Round)
//!
//! Each party P_i:
//! 1. c^0 = sum(phi_bar_k_j) = Enc(pk, phi * k)
//! 2. c^1 = phi_bar * H(m) + sum(phi_bar_x_j) * r_x = Enc(pk, phi*(H(m) + x*r_x))
//! 3. Partial decrypt: (pc_i^0, pi_0) <- t-CL.PartDec(pk, sk_i, c^0)
//! 4. Partial decrypt: (pc_i^1, pi_1) <- t-CL.PartDec(pk, sk_i, c^1)
//! 5. Broadcast (pc_i^0, pi_0, pc_i^1, pi_1)
//!
//! ## Output
//! 1. Verify all R_part-dec proofs
//! 2. p^0 <- t-CL.FinDec({pc_i^0}, c^0) -- recovers phi*k
//! 3. p^1 <- t-CL.FinDec({pc_i^1}, c^1) -- recovers phi*(H(m)+x*r_x)
//! 4. s = p^1 / p^0 mod q = k^{-1}(H(m) + x*r_x)
//! 5. Output (r_x, s) if ECDSA verify passes

#[cfg(feature = "robust")]
pub mod robust;

use std::collections::BTreeMap;

use elliptic_curve::PrimeField;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tecdsa_class_group::bicycl_glue::{BicyclCiphertext, BicyclPublicKey, BicyclQfi, ClSetup};
use tecdsa_class_group::zk::r_part_dec::RPartDecProof;
use tecdsa_core::TecdsaError;

use tecdsa_class_group::t_cl::{
    final_decrypt as threshold_cl_combine, PartialDecryption as ClPartialDecryption,
};
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::cl_wire::{SerRPartDecProof, SerializedQfi};
use crate::presign::Jtx25Presignature;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Jtx25OnlineSignMsg {
    Round3(Vec<u8>),
}

// Serialized types imported from crate::cl_wire

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R3Payload {
    pc_0: SerializedQfi,
    pi_0: SerRPartDecProof,
    pc_1: SerializedQfi,
    pi_1: SerRPartDecProof,
    /// Party index (1-based) for t-CL.FinDec.
    party_index: usize,
}

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

struct ReceivedR3 {
    pc_0: BicyclQfi,
    pc_1: BicyclQfi,
    party_index: usize,
}

// ---------------------------------------------------------------------------
// Message hashing
// ---------------------------------------------------------------------------

fn hash_message_to_scalar(message: &[u8]) -> k256::Scalar {
    let hash: [u8; 32] = Sha256::digest(message).into();
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(&hash);
    if let Some(s) = Option::from(k256::Scalar::from_repr(repr)) {
        return s;
    }
    repr[0] &= 0x7F;
    Option::from(k256::Scalar::from_repr(repr))
        .expect("scalar reduction must succeed after clearing top bit")
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

pub struct Jtx25OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    presignature: Jtx25Presignature,
    _message_hash: k256::Scalar,
    message: DataToSign<k256::Secp256k1>,
    public_key: k256::ProjectivePoint,
    c0: BicyclCiphertext,
    c1: BicyclCiphertext,
    setup: ClSetup,
    _cl_pk: BicyclPublicKey,
    cl_pk_shares: BTreeMap<u16, BicyclPublicKey>,
    received: BTreeMap<u16, ReceivedR3>,
    outgoing: Vec<Outgoing<Jtx25OnlineSignMsg>>,
    output: Option<Signature<k256::Secp256k1>>,
    ia_report: Option<IaReport>,
    done: bool,
}

impl Jtx25OnlineSignMachine {
    /// Create a new JTX25 Normal online signing state machine.
    ///
    /// Computes c^0 and c^1 from the presignature, then performs partial
    /// decryption and queues the broadcast.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Jtx25Presignature,
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

        let mut setup = if presignature.use_128bit_security {
            ClSetup::new_secp256k1_128bit(&presignature.cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(&presignature.cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup: {e}")))?;

        let ctx = setup.ctx();

        // Reconstruct phi_bar ciphertext.
        let pb_c1 = BicyclQfi::from_bytes(ctx, &presignature.phi_bar_c1_bytes)
            .map_err(|e| TecdsaError::Other(format!("phi_bar c1: {e}")))?;
        let pb_c2 = BicyclQfi::from_bytes(ctx, &presignature.phi_bar_c2_bytes)
            .map_err(|e| TecdsaError::Other(format!("phi_bar c2: {e}")))?;
        let phi_bar = setup
            .ct_from_components(&pb_c1, &pb_c2)
            .map_err(|e| TecdsaError::Other(format!("phi_bar ct: {e}")))?;

        // Reconstruct aggregate CL PK.
        let cl_pk_qfi = BicyclQfi::from_bytes(ctx, &presignature.cl_pk_bytes)
            .map_err(|e| TecdsaError::Other(format!("cl_pk: {e}")))?;
        let cl_pk = setup
            .pk_from_qfi(&cl_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("cl_pk from_qfi: {e}")))?;

        // Reconstruct per-party CL PK shares.
        let mut cl_pk_shares: BTreeMap<u16, BicyclPublicKey> = BTreeMap::new();
        for (&pid, bytes) in &presignature.cl_pk_share_bytes {
            let qfi = BicyclQfi::from_bytes(ctx, bytes)
                .map_err(|e| TecdsaError::Other(format!("cl_pk_share {pid}: {e}")))?;
            let pk = setup
                .pk_from_qfi(&qfi)
                .map_err(|e| TecdsaError::Other(format!("pk_from_qfi {pid}: {e}")))?;
            cl_pk_shares.insert(pid, pk);
        }

        // --- Compute c^0 = sum(phi_bar_k_j) ---
        // NO Lagrange weighting: k = sum(k_i) is n-out-of-n additive.
        let party_ids: Vec<u16> = all_parties.iter().map(|p| p.0).collect();
        let mut c0_opt: Option<BicyclCiphertext> = None;

        for &pid in &party_ids {
            let kc1_bytes = presignature
                .phi_bar_k_c1_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_k c1 for {pid}")))?;
            let kc2_bytes = presignature
                .phi_bar_k_c2_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_k c2 for {pid}")))?;

            let kc1 = BicyclQfi::from_bytes(ctx, kc1_bytes)
                .map_err(|e| TecdsaError::Other(format!("kc1: {e}")))?;
            let kc2 = BicyclQfi::from_bytes(ctx, kc2_bytes)
                .map_err(|e| TecdsaError::Other(format!("kc2: {e}")))?;
            let phi_bar_k_j = setup
                .ct_from_components(&kc1, &kc2)
                .map_err(|e| TecdsaError::Other(format!("phi_bar_k ct: {e}")))?;

            c0_opt = Some(match c0_opt.take() {
                None => phi_bar_k_j,
                Some(acc) => {
                    let (a1, a2) = setup
                        .ct_components(&acc)
                        .map_err(|e| TecdsaError::Other(format!("ct_comp: {e}")))?;
                    let (b1, b2) = setup
                        .ct_components(&phi_bar_k_j)
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

        // --- Compute c^1 = phi_bar * H(m) + sum(phi_bar_x_j) * r_x ---
        // phi_bar_x_j already contains lambda_j * x_j from presign.
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

        for &pid in &party_ids {
            let xc1_bytes = presignature
                .phi_bar_x_c1_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_x c1 for {pid}")))?;
            let xc2_bytes = presignature
                .phi_bar_x_c2_bytes
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing phi_bar_x c2 for {pid}")))?;

            let xc1 = BicyclQfi::from_bytes(ctx, xc1_bytes)
                .map_err(|e| TecdsaError::Other(format!("xc1: {e}")))?;
            let xc2 = BicyclQfi::from_bytes(ctx, xc2_bytes)
                .map_err(|e| TecdsaError::Other(format!("xc2: {e}")))?;
            let phi_bar_x_j = setup
                .ct_from_components(&xc1, &xc2)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

            // Multiply by r_x only (lambda is already baked in from presign).
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
        let my_party_index = presignature.party_index as usize + 1;
        let sk_share = &presignature.cl_sk_share;

        let my_pk_data = presignature
            .cl_pk_share_bytes
            .get(&presignature.party_index)
            .ok_or_else(|| TecdsaError::Other("missing own CL pk share".into()))?;
        let my_pk_qfi = BicyclQfi::from_bytes(ctx, my_pk_data)
            .map_err(|e| TecdsaError::Other(format!("my_pk: {e}")))?;
        let my_pk_raw = setup
            .pk_from_qfi(&my_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        let (c0_c1, _) = setup
            .ct_components(&c0)
            .map_err(|e| TecdsaError::Other(format!("c0 comp: {e}")))?;
        let pc_0 = setup
            .exp_bytes(&c0_c1, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pc_0: {e}")))?;
        let pi_0 = RPartDecProof::prove(&mut setup, &my_pk_raw, &c0, &pc_0, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pi_0: {e}")))?;

        let (c1_c1_comp, _) = setup
            .ct_components(&c1_ct)
            .map_err(|e| TecdsaError::Other(format!("c1 comp: {e}")))?;
        let pc_1 = setup
            .exp_bytes(&c1_c1_comp, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pc_1: {e}")))?;
        let pi_1 = RPartDecProof::prove(&mut setup, &my_pk_raw, &c1_ct, &pc_1, sk_share)
            .map_err(|e| TecdsaError::Other(format!("pi_1: {e}")))?;

        // Serialize and broadcast.
        let pc_0_ser = SerializedQfi::from_qfi(&setup, &pc_0)
            .map_err(|e| TecdsaError::Other(format!("ser pc_0: {e}")))?;
        let pi_0_ser = SerRPartDecProof::from_proof(&setup, &pi_0)
            .map_err(|e| TecdsaError::Other(format!("ser pi_0: {e}")))?;
        let pc_1_ser = SerializedQfi::from_qfi(&setup, &pc_1)
            .map_err(|e| TecdsaError::Other(format!("ser pc_1: {e}")))?;
        let pi_1_ser = SerRPartDecProof::from_proof(&setup, &pi_1)
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
            msg: Jtx25OnlineSignMsg::Round3(payload_bytes),
        }];

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

    fn try_finalize(&mut self) -> tecdsa_core::Result<()> {
        let n_parties_dkg = self.presignature.n_parties_dkg;
        let r_x = self.presignature.r_x;

        let mut pd_0s: Vec<ClPartialDecryption> = Vec::new();
        let mut pd_1s: Vec<ClPartialDecryption> = Vec::new();

        for r3 in self.received.values() {
            let ctx = self.setup.ctx();
            let pc0_bytes = r3
                .pc_0
                .to_bytes(ctx)
                .map_err(|e| TecdsaError::Other(format!("pc0 to_bytes: {e}")))?;
            let pc0_copy = BicyclQfi::from_bytes(ctx, &pc0_bytes)
                .map_err(|e| TecdsaError::Other(format!("pc0 from_bytes: {e}")))?;

            let pc1_bytes = r3
                .pc_1
                .to_bytes(ctx)
                .map_err(|e| TecdsaError::Other(format!("pc1 to_bytes: {e}")))?;
            let pc1_copy = BicyclQfi::from_bytes(ctx, &pc1_bytes)
                .map_err(|e| TecdsaError::Other(format!("pc1 from_bytes: {e}")))?;

            pd_0s.push(ClPartialDecryption {
                party_index: r3.party_index,
                dec_share: pc0_copy,
            });
            pd_1s.push(ClPartialDecryption {
                party_index: r3.party_index,
                dec_share: pc1_copy,
            });
        }

        let p0_bytes = threshold_cl_combine(&self.setup, &self.c0, n_parties_dkg, &pd_0s)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt c0: {e}")))?;

        let p1_bytes = threshold_cl_combine(&self.setup, &self.c1, n_parties_dkg, &pd_1s)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt c1: {e}")))?;

        let q_bytes = self
            .setup
            .q_bytes()
            .map_err(|e| TecdsaError::Other(format!("q_bytes: {e}")))?;
        let q = BigUint::from_bytes_be(&q_bytes);

        let p0 = BigUint::from_bytes_be(&p0_bytes);
        let p1 = BigUint::from_bytes_be(&p1_bytes);

        let q_minus_2 = &q - BigUint::from(2u32);
        let p0_inv = p0.modpow(&q_minus_2, &q);

        let s_big = (&p1 * &p0_inv) % &q;
        let s_raw = tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&s_big);
        let s = low_s_normalize::<k256::Secp256k1>(s_raw);

        let sig = Signature { r: r_x, s };

        if verify_ecdsa::<k256::Secp256k1>(&sig, &self.public_key, &self.message).is_ok() {
            self.output = Some(sig);
            self.done = true;
            return Ok(());
        }

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

impl StateMachine for Jtx25OnlineSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Jtx25OnlineSignMsg;
    type Outbound = Jtx25OnlineSignMsg;

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
            Jtx25OnlineSignMsg::Round3(data) => {
                let (payload, _): (R3Payload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R3: {e}")))?;

                let pc_0 = payload
                    .pc_0
                    .to_qfi(&self.setup)
                    .map_err(|e| TecdsaError::Other(format!("pc_0 from {from}: {e}")))?;
                let pi_0 = payload
                    .pi_0
                    .to_proof(&self.setup)
                    .map_err(|e| TecdsaError::Other(format!("pi_0 from {from}: {e}")))?;
                let pc_1 = payload
                    .pc_1
                    .to_qfi(&self.setup)
                    .map_err(|e| TecdsaError::Other(format!("pc_1 from {from}: {e}")))?;
                let pi_1 = payload
                    .pi_1
                    .to_proof(&self.setup)
                    .map_err(|e| TecdsaError::Other(format!("pi_1 from {from}: {e}")))?;

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

                if !pi_0_ok || !pi_1_ok {
                    return Err(TecdsaError::Other(format!(
                        "R_part_dec proof failed for {from}: pi_0={pi_0_ok}, pi_1={pi_1_ok}"
                    )));
                }

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
