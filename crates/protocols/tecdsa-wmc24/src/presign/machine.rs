// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 presign state machine.

use std::collections::BTreeMap;

use elliptic_curve::CurveArithmetic;
use rug::Integer;
use tecdsa_class_group::{
    cl::{ClSetup, Qfi},
    zk::r_enc::REncProof,
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::ddh::DdhStatement;
use tecdsa_elgamal::Ciphertext as ElGamalCiphertext;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{msg::*, rounds::*, QfiAbc, Wmc24Presignature};
use crate::{curve_wire::point_from_bytes, error::Wmc24Error, key_share::Wmc24KeyShare};

// ---------------------------------------------------------------------------
// Presign state machine
// ---------------------------------------------------------------------------

pub struct Wmc24PresignMachine {
    round: PresignRound,
    setup: ClSetup,
    key_mat: KeyMaterial,
}

impl Wmc24PresignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Wmc24KeyShare,
        mut setup: ClSetup,
    ) -> Result<Self, Wmc24Error> {
        if !all_parties.contains(&my_id) {
            return Err(Wmc24Error::InvalidInput("my_id not in all_parties".into()));
        }

        let threshold = key_share.threshold;

        let pk_elt = &key_share.cl_pk.elt();
        let cl_pk_abc = {
            let data = pk_elt.to_bytes();
            QfiAbc { data }
        };

        let mut cl_pk_share_abcs: BTreeMap<u16, QfiAbc> = BTreeMap::new();
        for (dkg_idx, qfi) in key_share.cl_pk_shares.iter().enumerate() {
            let pid = (dkg_idx + 1) as u16;
            let data = qfi.to_bytes();
            cl_pk_share_abcs.insert(pid, QfiAbc { data });
        }

        let key_mat = KeyMaterial {
            x_i: key_share.secret_share,
            public_shares: key_share.public_shares.clone(),
            threshold,
            cl_sk_share: key_share.cl_sk_share.clone(),
            cl_pk: setup.pk_from_qfi(pk_elt)?,
            cl_pk_abc,
            cl_pk_share_abcs,
            cl_setup_seed: key_share.cl_setup_seed.clone(),
            use_128bit_security: key_share.use_128bit_security,
            n_parties_dkg: key_share.n_parties_dkg,
            eldk_i: key_share.eldk_i,
            elek: key_share.elek,
            elek_shares: key_share.elek_shares.clone(),
        };

        // --- Round 1: Sample k_i, encrypt under threshold CL ---
        let k_i = {
            let (sk, _) = setup.keygen()?;
            let sk_dec = sk.to_string();
            let q_dec = setup.cl().q().to_string();
            let q = Integer::from_str_radix(&q_dec, 10)
                .map_err(|e| Wmc24Error::ScalarConversion(format!("parse q: {e}")))?;
            let bu = Integer::from_str_radix(&sk_dec, 10)
                .map_err(|e| Wmc24Error::ScalarConversion(format!("parse sk: {e}")))?;
            let reduced = bu % &q;
            tecdsa_curve::conv::integer_to_scalar::<k256::Secp256k1>(&reduced)
        };
        let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);

        let (r_sk, _) = setup.keygen()?;
        let enc_randomness = setup.sk_to_bytes(&r_sk)?;
        let k_bar_i = setup.encrypt_with_r_bytes(&key_mat.cl_pk, &k_i_bytes, &enc_randomness)?;

        let r_enc_proof = REncProof::prove(
            &mut setup,
            &key_mat.cl_pk,
            &k_bar_i,
            &k_i_bytes,
            &enc_randomness,
        )?;

        let k_bar_i_ser = SerializedClCt::from_bicycl_ct(&setup, &k_bar_i)
            .map_err(|e| Wmc24Error::InvalidInput(format!("serialize k_bar: {e}")))?;
        let r_enc_proof_ser = SerREncProof::from_proof(&r_enc_proof)
            .map_err(|e| Wmc24Error::InvalidInput(format!("serialize r_enc: {e}")))?;

        let r1_payload = R1Payload {
            k_bar_i: k_bar_i_ser,
            r_enc_proof: r_enc_proof_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Wmc24Error::InvalidInput(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Wmc24PresignMsg::Round1(payload_bytes),
        }];

        let mut received = BTreeMap::new();
        received.insert(my_id, ReceivedR1 { k_bar_i });

        let state = Round1State {
            my_id,
            all_parties,
            k_i,
            received,
            outgoing,
        };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup,
            key_mat,
        })
    }
}

// ---------------------------------------------------------------------------
// StateMachine implementation
// ---------------------------------------------------------------------------

impl StateMachine for Wmc24PresignMachine {
    type Output = Wmc24Presignature;
    type Inbound = Wmc24PresignMsg;
    type Outbound = Wmc24PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            PresignRound::Round1(s) => s.my_id,
            PresignRound::Round2(s) => s.my_id,
            PresignRound::Round3(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if let Wmc24PresignMsg::Round1(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R1Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

                    let k_bar_i = payload
                        .k_bar_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("k_bar from {from}: {e}")))?;

                    let r_enc_proof = payload
                        .r_enc_proof
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("r_enc from {from}: {e}")))?;

                    let r_enc_ok = r_enc_proof
                        .verify(&self.setup, &self.key_mat.cl_pk, &k_bar_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_enc verify from {from}: {e}"))
                        })?;

                    if !r_enc_ok {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "R_enc proof failed for party {from}"
                        )));
                    }

                    state.received.insert(from, ReceivedR1 { k_bar_i });

                    if state.received.len() == state.all_parties.len() {
                        let r2_state = transition_r1_to_r2(state, &mut self.setup, &self.key_mat)?;
                        self.round = PresignRound::Round2(r2_state);
                    } else {
                        self.round = PresignRound::Round1(state);
                    }
                } else {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 1".into()));
                }
            }

            PresignRound::Round2(mut state) => {
                if let Wmc24PresignMsg::Round2(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R2Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R2: {e}")))?;

                    let xk_bar_i = payload
                        .xk_bar_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("xk_bar from {from}: {e}")))?;
                    let gk_bar_i = payload
                        .gk_bar_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("gk_bar from {from}: {e}")))?;

                    // Decode ElGamal ciphertext.
                    let d_gamma_c0 = point_from_bytes(&payload.d_gamma_c0_bytes, "d_gamma_c0")
                        .map_err(TecdsaError::Other)?;
                    let d_gamma_c1 = point_from_bytes(&payload.d_gamma_c1_bytes, "d_gamma_c1")
                        .map_err(TecdsaError::Other)?;
                    let d_gamma_i = ElGamalCiphertext {
                        c0: d_gamma_c0,
                        c1: d_gamma_c1,
                    };

                    // Verify R_dl-cl proof.
                    let pi_dl_cl_x = payload
                        .pi_dl_cl_x
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_x from {from}: {e}")))?;

                    let from_idx = state
                        .all_parties
                        .iter()
                        .position(|p| *p == from)
                        .ok_or_else(|| TecdsaError::Other(format!("party {from} not found")))?;

                    let party_ids_1based: Vec<u16> =
                        state.all_parties.iter().map(|p| p.0).collect();
                    let lagrange_coeffs =
                        tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
                    let lambda_j = lagrange_coeffs[from_idx];

                    let from_dkg_idx = super::party_id_to_dkg_idx(from)?;
                    let x_j_lambda_point = self.key_mat.public_shares[from_dkg_idx] * lambda_j;

                    let dl_cl_x_ok = pi_dl_cl_x
                        .verify(&self.setup, &x_j_lambda_point, &state.k_bar, &xk_bar_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_dl-cl verify from {from}: {e}"))
                        })?;

                    // Verify R_El-CL proof.
                    let pi_el_cl = payload
                        .pi_el_cl
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_el_cl from {from}: {e}")))?;

                    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
                    let (ck_0, ck_1) = self
                        .setup
                        .ct_components(&state.k_bar)
                        .map_err(|e| TecdsaError::Other(format!("k_bar comp: {e}")))?;
                    let (cgk_0, cgk_1) = self
                        .setup
                        .ct_components(&gk_bar_i)
                        .map_err(|e| TecdsaError::Other(format!("gk_bar comp: {e}")))?;

                    let el_cl_ok = pi_el_cl
                        .verify(
                            &self.setup,
                            &g,
                            &self.key_mat.elek,
                            &d_gamma_i.c0,
                            &d_gamma_i.c1,
                            &ck_0,
                            &ck_1,
                            &cgk_0,
                            &cgk_1,
                        )
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_El-CL verify from {from}: {e}"))
                        })?;

                    if !(dl_cl_x_ok && el_cl_ok) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: dl_cl_x={dl_cl_x_ok}, el_cl={el_cl_ok}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR2 {
                            xk_bar_i,
                            d_gamma_i,
                            gk_bar_i,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let r3_state = transition_r2_to_r3(state, &mut self.setup, &self.key_mat)?;
                        self.round = PresignRound::Round3(r3_state);
                    } else {
                        self.round = PresignRound::Round2(state);
                    }
                } else {
                    self.round = PresignRound::Round2(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 2".into()));
                }
            }

            PresignRound::Round3(mut state) => {
                if let Wmc24PresignMsg::Round3(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R3Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R3: {e}")))?;

                    let pd_elg = point_from_bytes(&payload.pd_elg_bytes, "pd_elg")
                        .map_err(TecdsaError::Other)?;
                    let pd_cl = payload
                        .pd_cl
                        .to_qfi()
                        .map_err(|e| TecdsaError::Other(format!("pd_cl from {from}: {e}")))?;

                    // Verify DDH proof for ElGamal partial decryption.
                    // Statement: (G, D_gamma.c0, elek_j, pd_elg_j).
                    let pi_ddh = payload
                        .pi_part_dec_elg
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_ddh from {from}: {e}")))?;
                    let from_dkg_idx = payload.party_dkg_index;
                    if from_dkg_idx >= self.key_mat.elek_shares.len() {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!(
                            "party_dkg_index {from_dkg_idx} out of range for {from}"
                        )));
                    }
                    let from_elek = self.key_mat.elek_shares[from_dkg_idx];
                    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
                    let ddh_stmt = DdhStatement::<k256::Secp256k1> {
                        g,
                        a: state.d_gamma.c0,
                        b: from_elek,
                        c: pd_elg,
                    };
                    let pi_elg_ok = pi_ddh.verify(&ddh_stmt);

                    // Verify R_part_dec proof for CL.
                    let pi_part_dec_cl = payload
                        .pi_part_dec_cl
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_part_dec from {from}: {e}")))?;

                    let from_pk_abc =
                        self.key_mat.cl_pk_share_abcs.get(&from.0).ok_or_else(|| {
                            TecdsaError::Other(format!("missing CL pk share for {from}"))
                        })?;
                    let from_pk_qfi = { Qfi::from_bytes(&from_pk_abc.data) };
                    let from_pk_raw = self
                        .setup
                        .pk_from_qfi(&from_pk_qfi)
                        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

                    let pi_cl_ok = pi_part_dec_cl
                        .verify(&self.setup, &from_pk_raw, &state.gk_bar, &pd_cl)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_part_dec verify from {from}: {e}"))
                        })?;

                    if !(pi_elg_ok && pi_cl_ok) {
                        self.round = PresignRound::Round3(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: \
                             pi_part_dec_elg={pi_elg_ok}, pi_part_dec_cl={pi_cl_ok}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR3 {
                            pd_elg,
                            pd_cl,
                            party_index: payload.party_index,
                            party_dkg_index: from_dkg_idx,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let presignature = finalize(&state, &self.setup, &self.key_mat)?;
                        self.round = PresignRound::Done(presignature);
                    } else {
                        self.round = PresignRound::Round3(state);
                    }
                } else {
                    self.round = PresignRound::Round3(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 3".into()));
                }
            }

            PresignRound::Done(_) => {
                return Err(TecdsaError::Other("presign already complete".into()));
            }
            PresignRound::Poisoned => {
                return Err(TecdsaError::Other("presign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round2(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round3(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Round3(_) => 3,
            PresignRound::Done(_) => 4,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
