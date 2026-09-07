// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 online sign state machine.

use std::collections::BTreeMap;

use rug::Integer;
use tecdsa_bigint::BigIntExt;
use tecdsa_class_group::{
    cl::{parse_int_auto, ClCiphertext, ClPublicKey, ClSetup, Qfi},
    t_cl::{self as threshold_cl, PartialDecryption as ClPartialDecryption},
    zk::r_part_dec::RPartDecProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::{ScalarExt, TecdsaCurve};
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
    state_machine::Outgoing,
    IaReport, PartyId, Recipient, StateMachine,
};

use super::{msg::*, rounds::*};
use crate::presign::Wmc24Presignature;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

pub struct Wmc24OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    presignature: Wmc24Presignature,
    _message_hash: k256::Scalar,
    message: DataToSign<k256::Secp256k1>,
    public_key: k256::ProjectivePoint,
    /// The combined ciphertext Enc(km + rkx).
    c_sig: ClCiphertext,
    setup: ClSetup,
    _cl_pk: ClPublicKey,
    cl_pk_shares: BTreeMap<u16, ClPublicKey>,
    received: BTreeMap<u16, ReceivedR4>,
    outgoing: Vec<Outgoing<Wmc24OnlineSignMsg>>,
    output: Option<Signature<k256::Secp256k1>>,
    ia_report: Option<IaReport>,
    done: bool,
}

impl Wmc24OnlineSignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Wmc24Presignature,
        message: &[u8],
        public_key: k256::ProjectivePoint,
    ) -> tecdsa_core::Result<Self> {
        // Rebuild the (global) CL public parameters from the stored seed, then
        // delegate. Benches holding the shared `ClSetup` call `new_with_setup`
        // to avoid timing this one-time global setup as online-sign cost.
        let seed = parse_int_auto(&presignature.cl_setup_seed)
            .map_err(|e| TecdsaError::Other(format!("cl_setup_seed parse failed: {e}")))?;
        let setup = if presignature.use_128bit_security {
            ClSetup::new_secp256k1_128bit(&seed)
        } else {
            ClSetup::new_secp256k1(&seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup: {e}")))?;
        Self::new_with_setup(my_id, all_parties, presignature, message, public_key, setup)
    }

    /// Like [`new`](Self::new) but reuses a pre-built [`ClSetup`] (the global CL
    /// public parameters) instead of reconstructing it from the presignature seed.
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Wmc24Presignature,
        message: &[u8],
        public_key: k256::ProjectivePoint,
        mut setup: ClSetup,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }

        let m = hash_message_to_scalar(message);
        let m_int = m.to_integer();
        let message_data = DataToSign::from_digest(m);
        let r_x = presignature.r_x;
        let r_x_int = r_x.to_integer();

        // Reconstruct k_bar ciphertext.
        let kb_c1 = Qfi::from_bytes(&presignature.k_bar_c1_abc.data);
        let kb_c2 = Qfi::from_bytes(&presignature.k_bar_c2_abc.data);
        let k_bar = setup
            .ct_from_components(&kb_c1, &kb_c2)
            .map_err(|e| TecdsaError::Other(format!("k_bar ct: {e}")))?;

        // Reconstruct xk_bar ciphertext.
        let xk_c1 = Qfi::from_bytes(&presignature.xk_bar_c1_abc.data);
        let xk_c2 = Qfi::from_bytes(&presignature.xk_bar_c2_abc.data);
        let xk_bar = setup
            .ct_from_components(&xk_c1, &xk_c2)
            .map_err(|e| TecdsaError::Other(format!("xk_bar ct: {e}")))?;

        // Reconstruct aggregate CL PK.
        let cl_pk_qfi = Qfi::from_bytes(&presignature.cl_pk_abc.data);
        let cl_pk = setup
            .pk_from_qfi(&cl_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("cl_pk from_qfi: {e}")))?;

        // Reconstruct per-party CL PK shares.
        let mut cl_pk_shares: BTreeMap<u16, ClPublicKey> = BTreeMap::new();
        for (&pid, abc) in &presignature.cl_pk_share_abcs {
            let qfi = Qfi::from_bytes(&abc.data);
            let pk = setup
                .pk_from_qfi(&qfi)
                .map_err(|e| TecdsaError::Other(format!("pk_from_qfi {pid}: {e}")))?;
            cl_pk_shares.insert(pid, pk);
        }

        // Compute Enc(km + rkx) = (m * k_bar) + (r * xk_bar).
        // m * k_bar: component-wise exponentiation.
        let (kb_c1_comp, kb_c2_comp) = setup
            .ct_components(&k_bar)
            .map_err(|e| TecdsaError::Other(format!("k_bar comp: {e}")))?;
        let (xk_c1_comp, xk_c2_comp) = setup
            .ct_components(&xk_bar)
            .map_err(|e| TecdsaError::Other(format!("xk_bar comp: {e}")))?;

        // Each signature ciphertext component is the two-base product
        // `k_bar^m · xk_bar^{r_x}`; fold it with one shared-squaring
        // dual-exponentiation instead of two exps + a compose.
        let exps = [m_int.clone(), r_x_int.clone()];
        let sig_c1 = setup
            .multiexp(&[&kb_c1_comp, &xk_c1_comp], &exps)
            .map_err(|e| TecdsaError::Other(format!("dualexp sig c1: {e}")))?;
        let sig_c2 = setup
            .multiexp(&[&kb_c2_comp, &xk_c2_comp], &exps)
            .map_err(|e| TecdsaError::Other(format!("dualexp sig c2: {e}")))?;
        let c_sig = setup
            .ct_from_components(&sig_c1, &sig_c2)
            .map_err(|e| TecdsaError::Other(format!("ct_from sig: {e}")))?;

        // Partial decrypt c_sig.
        // party_index is 1-based (matches PartyId convention and t-CL evaluation points).
        let my_party_index = presignature.party_index as usize;
        let sk_share = Integer::from_bytes_msf(&presignature.cl_sk_share);

        let my_pk_abc = presignature
            .cl_pk_share_abcs
            .get(&presignature.party_index)
            .ok_or_else(|| TecdsaError::Other("missing own CL pk share".into()))?;
        let my_pk_qfi = Qfi::from_bytes(&my_pk_abc.data);
        let my_pk_raw = setup
            .pk_from_qfi(&my_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        let (sig_c1_comp, _) = setup
            .ct_components(&c_sig)
            .map_err(|e| TecdsaError::Other(format!("c_sig comp: {e}")))?;
        let pc = setup
            .exp(&sig_c1_comp, &sk_share)
            .map_err(|e| TecdsaError::Other(format!("pc: {e}")))?;
        let pi = RPartDecProof::prove(&mut setup, &my_pk_raw, &c_sig, &pc, &sk_share)
            .map_err(|e| TecdsaError::Other(format!("pi: {e}")))?;

        let pc_ser =
            SerializedQfi::from_qfi(&pc).map_err(|e| TecdsaError::Other(format!("ser pc: {e}")))?;
        let pi_ser = SerRPartDecProof::from_proof(&pi)
            .map_err(|e| TecdsaError::Other(format!("ser pi: {e}")))?;

        let r4_payload = R4Payload {
            pc: pc_ser,
            pi: pi_ser,
            party_index: my_party_index,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r4_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R4: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Wmc24OnlineSignMsg::Round4(payload_bytes),
        }];

        let mut received = BTreeMap::new();
        received.insert(
            presignature.party_index,
            ReceivedR4 {
                pc,
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
            c_sig,
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

        let mut pd_s: Vec<ClPartialDecryption> = Vec::new();
        for r4 in self.received.values() {
            let bytes = r4.pc.to_bytes();
            let copy = Qfi::from_bytes(&bytes);
            pd_s.push(ClPartialDecryption {
                party_index: r4.party_index,
                dec_share: copy,
            });
        }

        let s_int = threshold_cl::final_decrypt(&self.setup, &self.c_sig, n_parties_dkg, &pd_s)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt: {e}")))?;

        // s = km + rkx -- this is already the s value for ECDSA with R = g^{1/k}.
        // ECDSA verify: g^{s^{-1}m} * X^{s^{-1}r} = g^{(m+rx)/s} = g^{(m+rx)/(km+rkx)} = g^{1/k} = R
        let s_raw = k256::Secp256k1::scalar_from_integer(&s_int);
        let s = low_s_normalize::<k256::Secp256k1>(s_raw);

        let sig = Signature { r: r_x, s };

        if verify_ecdsa::<k256::Secp256k1>(&sig, &self.public_key, &self.message).is_ok() {
            self.output = Some(sig);
            self.done = true;
            return Ok(());
        }

        // Try with negated s.
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

impl StateMachine for Wmc24OnlineSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Wmc24OnlineSignMsg;
    type Outbound = Wmc24OnlineSignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if self.done {
            return Err(TecdsaError::Other("machine already done".into()));
        }

        // Reject messages from self.
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        let from_pid = from.0;
        if self.received.contains_key(&from_pid) {
            return Err(TecdsaError::Other(format!("duplicate from {from}")));
        }

        match msg {
            Wmc24OnlineSignMsg::Round4(data) => {
                let (payload, _): (R4Payload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R4: {e}")))?;

                let pc = payload
                    .pc
                    .to_qfi()
                    .map_err(|e| TecdsaError::Other(format!("pc from {from}: {e}")))?;
                let pi = payload
                    .pi
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("pi from {from}: {e}")))?;

                let from_pk = self
                    .cl_pk_shares
                    .get(&from_pid)
                    .ok_or_else(|| TecdsaError::Other(format!("missing CL pk share for {from}")))?;

                let pi_ok = pi
                    .verify(&self.setup, from_pk, &self.c_sig, &pc)
                    .map_err(|e| TecdsaError::Other(format!("pi verify from {from}: {e}")))?;

                if !pi_ok {
                    return Err(TecdsaError::Other(format!(
                        "R_part_dec proof failed for {from}"
                    )));
                }

                self.received.insert(
                    from_pid,
                    ReceivedR4 {
                        pc,
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
            5
        } else {
            4
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
