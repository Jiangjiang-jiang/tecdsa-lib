use std::collections::BTreeMap;

use tecdsa_class_group::cl::{ClPublicKey, ClSetup, Qfi};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
use zeroize::Zeroize;

use super::{
    msg::{
        R1Payload, R2Payload, SerREncProof, SerRShProof, SerializedClCt, SerializedQfi,
        Tx25PresignMsg,
    },
    rounds::{
        finalize, my_idx, n_others, point_from_bytes, transition_r1_to_r2, PresignRound,
        ReceivedR1, ReceivedR2, Round1State,
    },
    KeyMaterial, Tx25Presignature,
};
use crate::{
    error::Tx25Error, key_share::Tx25KeyShare, mpmta::mpmta_round1, pvss::pvss_distribute,
};

pub struct Tx25PresignMachine {
    pub(crate) round: PresignRound,
    pub(crate) setup: ClSetup,
    pub(crate) key_mat: KeyMaterial,
}

impl Tx25PresignMachine {
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Tx25KeyShare,
        mut setup: ClSetup,
    ) -> Result<Self, Tx25Error> {
        if !all_parties.contains(&my_id) {
            return Err(Tx25Error::InvalidInput(
                "my_id not found in all_parties".into(),
            ));
        }

        let my_idx_val = my_idx(&all_parties, my_id)
            .ok_or_else(|| Tx25Error::InvalidInput("my_id not in all_parties".into()))?;
        let threshold = key_share.threshold;

        let sk_decimal = setup
            .sk_to_bytes(&key_share.cl_sk)
            .map_err(|e| Tx25Error::InvalidInput(format!("sk_to_bytes: {e}")))?;

        let active_indices: Vec<usize> = all_parties
            .iter()
            .map(|party| {
                let idx = party.0.checked_sub(1).ok_or_else(|| {
                    Tx25Error::InvalidInput(format!("invalid zero party id: {party}"))
                })? as usize;

                if idx >= key_share.cl_pks.len() {
                    return Err(Tx25Error::InvalidInput(format!(
                        "{party} has no CL public key ({} available)",
                        key_share.cl_pks.len()
                    )));
                }
                if idx >= key_share.public_shares.len() {
                    return Err(Tx25Error::InvalidInput(format!(
                        "{party} has no public share ({} available)",
                        key_share.public_shares.len()
                    )));
                }

                Ok(idx)
            })
            .collect::<Result<_, _>>()?;

        let raw_pks: Vec<ClPublicKey> = active_indices
            .iter()
            .map(|&idx| {
                let qfi = key_share.cl_pks[idx].elt();
                setup.pk_from_qfi(qfi)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let public_shares: Vec<k256::ProjectivePoint> = active_indices
            .iter()
            .map(|&idx| key_share.public_shares[idx])
            .collect();

        let key_mat = KeyMaterial {
            sk_decimal,
            raw_pks,
            x_i: key_share.secret_share,
            public_key: key_share.public_key,
            public_shares,
            threshold,
        };

        let mut rng = rand::thread_rng();

        let gamma_i = k256::Secp256k1::random_scalar(&mut rng);

        let gamma_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&gamma_i);
        let my_pk = &key_mat.raw_pks[my_idx_val];
        let mpmta_r1 = mpmta_round1(&mut setup, my_pk, &gamma_bytes)?;

        let party_ids_u16: Vec<u16> = all_parties.iter().map(|p| p.0).collect();

        let pvss_out = pvss_distribute(
            &mut setup,
            &party_ids_u16,
            &key_mat.raw_pks,
            threshold,
            my_idx_val,
            &mut rng,
        )?;

        let c_gamma_ser = SerializedClCt::from_bicycl_ct(&mpmta_r1.ciphertext)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize c_gamma: {e}")))?;

        let r_enc_proof_ser = SerREncProof::from_proof(&mpmta_r1.proof)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize r_enc_proof: {e}")))?;

        let pvss_c1_ser = SerializedQfi::from_qfi(&pvss_out.c1)
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize pvss_c1: {e}")))?;

        let pvss_c2s_ser: Vec<SerializedQfi> = pvss_out
            .c2s
            .iter()
            .map(|c2| {
                SerializedQfi::from_qfi(c2)
                    .map_err(|e| Tx25Error::InvalidInput(format!("serialize pvss_c2: {e}")))
            })
            .collect::<Result<_, _>>()?;

        let pvss_proof_ser = SerRShProof::from_proof(&pvss_out.proof);

        let r1_payload = R1Payload {
            c_gamma: c_gamma_ser,
            r_enc_proof: r_enc_proof_ser,
            pvss_c1: pvss_c1_ser,
            pvss_c2s: pvss_c2s_ser,
            pvss_proof: pvss_proof_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Tx25Error::InvalidInput(format!("serialize R1 payload: {e}")))?;

        let mut outgoing = Vec::new();
        for &party in &all_parties {
            if party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(party),
                    msg: Tx25PresignMsg::Round1(payload_bytes.clone()),
                });
            }
        }

        let own_pvss_share = pvss_out.secret_share;
        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                c_gamma: mpmta_r1.ciphertext,
                r_enc_proof: mpmta_r1.proof,
                pvss_c1: pvss_out.c1,
                pvss_c2s: pvss_out.c2s,
                pvss_proof: pvss_out.proof,
            },
        );

        let state = Round1State {
            my_id,
            all_parties,
            gamma_i,
            own_pvss_share,
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

impl StateMachine for Tx25PresignMachine {
    type Output = Tx25Presignature;
    type Inbound = Tx25PresignMsg;
    type Outbound = Tx25PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let my_id = match &self.round {
            PresignRound::Round1(s) => s.my_id,
            PresignRound::Round2(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if let Tx25PresignMsg::Round1(data) = msg {
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
                            .map_err(|e| {
                                self.round = PresignRound::Poisoned;
                                TecdsaError::Other(format!("deserialize R1 payload: {e}"))
                            })?;

                    let c_gamma = payload.c_gamma.to_bicycl_ct().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct c_gamma from party {from}: {e}"))
                    })?;

                    let r_enc_proof = payload.r_enc_proof.to_proof().map_err(|e| {
                        TecdsaError::Other(format!(
                            "reconstruct r_enc_proof from party {from}: {e}"
                        ))
                    })?;

                    let pvss_c1 = payload.pvss_c1.to_qfi().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pvss_c1 from party {from}: {e}"))
                    })?;

                    let pvss_c2s: Vec<Qfi> = payload
                        .pvss_c2s
                        .iter()
                        .map(|s| {
                            s.to_qfi().map_err(|e| {
                                TecdsaError::Other(format!(
                                    "reconstruct pvss_c2 from party {from}: {e}"
                                ))
                            })
                        })
                        .collect::<Result<_, _>>()?;

                    let pvss_proof = payload.pvss_proof.to_proof();

                    state.received.insert(
                        from,
                        ReceivedR1 {
                            c_gamma,
                            r_enc_proof,
                            pvss_c1,
                            pvss_c2s,
                            pvss_proof,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let r2_state = transition_r1_to_r2(state, &mut self.setup, &self.key_mat)?;
                        self.round = PresignRound::Round2(r2_state);
                    } else {
                        self.round = PresignRound::Round1(state);
                    }
                } else {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 1".into(),
                    ));
                }
            }

            PresignRound::Round2(mut state) => {
                if let Tx25PresignMsg::Round2(data) = msg {
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
                            .map_err(|e| {
                                TecdsaError::Other(format!("deserialize R2 payload: {e}"))
                            })?;

                    let n = state.all_parties.len();
                    if payload.mta_outputs.len() != n {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "R2 mta_outputs length mismatch: expected {n}, got {}",
                            payload.mta_outputs.len()
                        )));
                    }

                    let mut kg_c_alphas = Vec::with_capacity(n);
                    let mut xg_c_alphas = Vec::with_capacity(n);
                    let mut b_pts = Vec::with_capacity(n);
                    let mut b_hat_pts = Vec::with_capacity(n);

                    for (j, mta) in payload.mta_outputs.iter().enumerate() {
                        let kg_ca = mta.c_alpha.to_bicycl_ct().map_err(|e| {
                            TecdsaError::Other(format!(
                                "reconstruct kg c_alpha[{j}] from party {from}: {e}"
                            ))
                        })?;
                        let xg_ca = mta.c_alpha_hat.to_bicycl_ct().map_err(|e| {
                            TecdsaError::Other(format!(
                                "reconstruct xg c_alpha[{j}] from party {from}: {e}"
                            ))
                        })?;
                        let bp =
                            point_from_bytes(&mta.b_point_bytes, &format!("B[{j}] from {from}"))
                                .map_err(TecdsaError::Other)?;
                        let bhp = point_from_bytes(
                            &mta.b_hat_point_bytes,
                            &format!("B_hat[{j}] from {from}"),
                        )
                        .map_err(TecdsaError::Other)?;

                        kg_c_alphas.push(kg_ca);
                        xg_c_alphas.push(xg_ca);
                        b_pts.push(bp);
                        b_hat_pts.push(bhp);
                    }

                    let r_point =
                        point_from_bytes(&payload.r_point_bytes, &format!("R from {from}"))
                            .map_err(TecdsaError::Other)?;

                    let pd = payload.pd.to_qfi().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pd from party {from}: {e}"))
                    })?;

                    let pd_c1 = payload.pd_c1.to_qfi().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct pd_c1 from party {from}: {e}"))
                    })?;

                    let dec_dl_proof = payload.dec_dl_proof.to_proof().map_err(|e| {
                        TecdsaError::Other(format!(
                            "reconstruct dec_dl_proof from party {from}: {e}"
                        ))
                    })?;

                    let kg_proof = payload.kg_proof.to_proof().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct kg_proof from party {from}: {e}"))
                    })?;

                    let xg_proof = payload.xg_proof.to_proof().map_err(|e| {
                        TecdsaError::Other(format!("reconstruct xg_proof from party {from}: {e}"))
                    })?;

                    state.received.insert(
                        from,
                        ReceivedR2 {
                            kg_c_alphas,
                            xg_c_alphas,
                            b_points: b_pts,
                            b_hat_points: b_hat_pts,
                            r_point,
                            pd,
                            pd_c1,
                            dec_dl_proof,
                            kg_proof,
                            xg_proof,
                        },
                    );

                    if state.received.len() == n_others(&state.all_parties) {
                        let presignature = finalize(&state, &self.setup, &self.key_mat)?;
                        state.gamma_i.zeroize();
                        state.k_i.zeroize();
                        self.round = PresignRound::Done(presignature);
                    } else {
                        self.round = PresignRound::Round2(state);
                    }
                } else {
                    self.round = PresignRound::Round2(state);
                    return Err(TecdsaError::Other(
                        "unexpected message type in round 2".into(),
                    ));
                }
            }

            PresignRound::Done(_) => {
                return Err(TecdsaError::Other(
                    "presign already complete, no more messages expected".into(),
                ));
            }

            PresignRound::Poisoned => {
                return Err(TecdsaError::Other(
                    "presign machine is in poisoned state (previous transition failed)".into(),
                ));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round2(s) => std::mem::take(&mut s.outgoing),
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
            PresignRound::Done(_) => 3,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::CurveArithmetic;
    use tecdsa_class_group::cl::ClSetup;

    use super::*;

    #[test]
    fn new_accepts_active_signer_subset_from_full_key_share() {
        let seed = "90001";
        let mut setup = ClSetup::new_secp256k1(seed).expect("setup");

        let (_, cl_pk_1) = setup.keygen().expect("cl keygen 1");
        let (cl_sk_2, cl_pk_2) = setup.keygen().expect("cl keygen 2");
        let (_, cl_pk_3) = setup.keygen().expect("cl keygen 3");

        let generator = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let public_shares = vec![
            generator * k256::Scalar::from(1u64),
            generator * k256::Scalar::from(2u64),
            generator * k256::Scalar::from(3u64),
        ];
        let expected_active_public_shares = vec![public_shares[1], public_shares[2]];

        let key_share = Tx25KeyShare {
            party_index: 2,
            secret_share: k256::Scalar::from(2u64),
            public_key: public_shares[0] + public_shares[1] + public_shares[2],
            public_shares,
            cl_sk: cl_sk_2,
            cl_pks: vec![cl_pk_1, cl_pk_2, cl_pk_3],
            cl_setup_seed: seed.to_string(),
            use_128bit_security: false,
            threshold: 1,
            total: 3,
        };

        let active_signers = vec![PartyId(2), PartyId(3)];
        let presign_setup = ClSetup::new_secp256k1(seed).expect("presign setup");

        let result = Tx25PresignMachine::new(PartyId(2), active_signers, &key_share, presign_setup);

        let machine = match result {
            Ok(machine) => machine,
            Err(err) => {
                panic!("active signer subset should use only active parties' key material: {err}")
            }
        };

        assert_eq!(machine.key_mat.raw_pks.len(), 2);
        assert_eq!(machine.key_mat.public_shares, expected_active_public_shares);
    }
}
