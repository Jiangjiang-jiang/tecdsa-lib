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

use std::collections::BTreeMap;

use elliptic_curve::PrimeField;
use rand::RngCore;
use tecdsa_class_group::cl::{ClPublicKey as ClHsmqkPublicKey, ClSetup};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
use zeroize::Zeroize;

use super::{
    msg::Llz25KeygenMsg,
    rounds::{
        compute_commitment, proj_from_bytes, scalar_to_bytes, R1LocalState, R2BcastPayload,
        R2ReceivedBcast, R3Payload, R3ReceivedData, SerDlogProof,
    },
};
use crate::key_share::Llz25KeyShare;

pub struct Llz25KeygenMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    setup: ClSetup,
    pk_crs: ClHsmqkPublicKey,
    cl_setup_seed: String,
    use_128bit: bool,
    round: u16,

    r1_state: Option<R1LocalState>,
    r1_commitments: BTreeMap<PartyId, [u8; 32]>,

    r2_bcasts: BTreeMap<PartyId, R2ReceivedBcast>,
    r2_shares: BTreeMap<PartyId, k256::Scalar>,

    r3_data: BTreeMap<PartyId, R3ReceivedData>,

    stash_combined_share: Option<k256::Scalar>,
    stash_st_x_bytes: Option<Vec<u8>>,
    stash_public_key: Option<k256::ProjectivePoint>,
    stash_public_shares: Option<Vec<k256::ProjectivePoint>>,

    outgoing: Vec<Outgoing<Llz25KeygenMsg>>,
    output: Option<Llz25KeyShare>,
    done: bool,
}

impl Llz25KeygenMachine {
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit: bool,
        pk_crs: ClHsmqkPublicKey,
        setup: ClSetup,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }

        let n = all_parties.len() as u16;

        let mut rng = rand::rngs::OsRng;

        let x_i = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let (vss_shares, vss_commitments) =
            tecdsa_vss::feldman::split::<k256::Secp256k1>(&x_i, threshold, n, &mut rng);

        let a_i_0 = vss_commitments[0];
        let ephemeral = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let dlog_proof = tecdsa_curve::zk::dlog::DlogProof::<k256::Secp256k1>::prove(
            &x_i,
            &ephemeral,
            &a_i_0,
            b"llz25-dkg-dlog",
        );

        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let commitment = compute_commitment(&nonce, &vss_commitments, &dlog_proof);

        let mut r1_commitments = BTreeMap::new();
        r1_commitments.insert(my_id, commitment);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Llz25KeygenMsg::Round1(commitment.to_vec()),
        }];

        let r1_local = R1LocalState {
            x_i,
            vss_shares,
            vss_commitments,
            dlog_proof,
            nonce,
        };

        Ok(Self {
            my_id,
            all_parties,
            threshold,
            setup,
            pk_crs,
            cl_setup_seed: cl_setup_seed.to_string(),
            use_128bit,
            round: 1,
            r1_state: Some(r1_local),
            r1_commitments,
            r2_bcasts: BTreeMap::new(),
            r2_shares: BTreeMap::new(),
            r3_data: BTreeMap::new(),
            stash_combined_share: None,
            stash_st_x_bytes: None,
            stash_public_key: None,
            stash_public_shares: None,
            outgoing,
            output: None,
            done: false,
        })
    }

    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit: bool,
        pk_crs: ClHsmqkPublicKey,
    ) -> tecdsa_core::Result<Self> {
        let setup = if use_128bit {
            ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        Self::new_with_setup(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit,
            pk_crs,
            setup,
        )
    }

    fn n(&self) -> usize {
        self.all_parties.len()
    }

    fn my_1based_index(&self) -> tecdsa_core::Result<u16> {
        self.all_parties
            .iter()
            .position(|p| *p == self.my_id)
            .map(|i| i as u16 + 1)
            .ok_or_else(|| TecdsaError::Other("my_id must be in all_parties".into()))
    }

    fn party_1based_index(&self, party: PartyId) -> Option<u16> {
        self.all_parties
            .iter()
            .position(|p| *p == party)
            .map(|i| i as u16 + 1)
    }

    fn transition_to_r2(&mut self) -> tecdsa_core::Result<()> {
        let r1 = self
            .r1_state
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("r1_state missing".into()))?;

        let vss_com_bytes: Vec<Vec<u8>> = r1
            .vss_commitments
            .iter()
            .map(super::rounds::proj_to_bytes)
            .collect();

        let r2_payload = R2BcastPayload {
            nonce: r1.nonce.to_vec(),
            vss_commitment_points: vss_com_bytes,
            dlog_proof: SerDlogProof::from_proof(&r1.dlog_proof),
        };

        let r2_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2 bcast: {e}")))?;

        self.r2_bcasts.insert(
            self.my_id,
            R2ReceivedBcast {
                nonce: r1.nonce,
                vss_commitments: r1.vss_commitments.clone(),
                dlog_proof: r1.dlog_proof.clone(),
            },
        );

        let my_1based = self.my_1based_index()?;
        let my_share_value = r1
            .vss_shares
            .iter()
            .find(|s| s.index == my_1based)
            .ok_or_else(|| TecdsaError::Other("own VSS share must exist".into()))?
            .value;
        self.r2_shares.insert(self.my_id, my_share_value);

        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Llz25KeygenMsg::Round2Bcast(r2_bytes),
        });

        for &party in &self.all_parties {
            if party == self.my_id {
                continue;
            }
            let j_1based = self
                .party_1based_index(party)
                .ok_or_else(|| TecdsaError::Other("party not found".into()))?;
            let share_for_j = r1
                .vss_shares
                .iter()
                .find(|s| s.index == j_1based)
                .ok_or_else(|| {
                    TecdsaError::Other(format!("VSS share for party {party} must exist"))
                })?;
            let share_bytes = scalar_to_bytes(&share_for_j.value);
            self.outgoing.push(Outgoing {
                to: Recipient::Party(party),
                msg: Llz25KeygenMsg::Round2Share(share_bytes),
            });
        }

        self.round = 2;
        Ok(())
    }

    fn transition_to_r3(&mut self) -> tecdsa_core::Result<()> {
        let my_1based = self.my_1based_index()?;

        let (combined_share, st_x_bytes, public_key, public_shares, r3_bytes) =
            super::rounds::transition_to_r3(
                self.my_id,
                &self.all_parties,
                my_1based,
                &self.r1_commitments,
                &self.r2_bcasts,
                &self.r2_shares,
                &mut self.setup,
                &self.pk_crs,
                &mut self.r3_data,
            )?;

        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Llz25KeygenMsg::Round3(r3_bytes),
        });

        self.stash_combined_share = Some(combined_share);
        self.stash_st_x_bytes = Some(st_x_bytes);
        self.stash_public_key = Some(public_key);
        self.stash_public_shares = Some(public_shares);

        self.round = 3;
        Ok(())
    }

    fn finalize(&mut self) -> tecdsa_core::Result<()> {
        let _r1_state = self
            .r1_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r1_state missing in finalize".into()))?;

        let combined_share = self
            .stash_combined_share
            .take()
            .ok_or_else(|| TecdsaError::Other("combined_share missing".into()))?;
        let st_x_bytes = self
            .stash_st_x_bytes
            .take()
            .ok_or_else(|| TecdsaError::Other("st_x_bytes missing".into()))?;
        let public_key = self
            .stash_public_key
            .take()
            .ok_or_else(|| TecdsaError::Other("public_key missing".into()))?;
        let public_shares = self
            .stash_public_shares
            .take()
            .ok_or_else(|| TecdsaError::Other("public_shares missing".into()))?;

        let my_1based = self.my_1based_index()?;

        let key_share = super::rounds::finalize(
            self.my_id,
            &self.all_parties,
            my_1based,
            &self.r3_data,
            &mut self.setup,
            &self.pk_crs,
            combined_share,
            st_x_bytes,
            public_key,
            &public_shares,
            &self.cl_setup_seed,
            self.use_128bit,
            self.threshold,
        )?;

        self.output = Some(key_share);
        self.done = true;
        Ok(())
    }

    fn check_r2_complete(&mut self) -> tecdsa_core::Result<()> {
        if self.r2_bcasts.len() == self.n() && self.r2_shares.len() == self.n() {
            self.transition_to_r3()?;
        }
        Ok(())
    }
}

impl Drop for Llz25KeygenMachine {
    fn drop(&mut self) {
        for share in self.r2_shares.values_mut() {
            share.zeroize();
        }
        if let Some(ref mut s) = self.stash_combined_share {
            s.zeroize();
        }
        if let Some(ref mut s) = self.stash_st_x_bytes {
            s.zeroize();
        }
    }
}

impl StateMachine for Llz25KeygenMachine {
    type Output = Llz25KeyShare;
    type Inbound = Llz25KeygenMsg;
    type Outbound = Llz25KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        match msg {
            Llz25KeygenMsg::Round1(data) => {
                if self.round != 1 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round1 in round {}",
                        self.round
                    )));
                }
                if self.r1_commitments.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid R1 commitment length".into()));
                }
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&data);
                self.r1_commitments.insert(from, commitment);

                if self.r1_commitments.len() == self.n() {
                    self.transition_to_r2()?;
                }
            }

            Llz25KeygenMsg::Round2Bcast(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Bcast in round {}",
                        self.round
                    )));
                }
                if self.r2_bcasts.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let (payload, _): (R2BcastPayload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R2 bcast: {e}")))?;

                let vss_commitments: Vec<k256::ProjectivePoint> = payload
                    .vss_commitment_points
                    .iter()
                    .map(|bytes| proj_from_bytes(bytes))
                    .collect::<Result<Vec<_>, _>>()?;

                let mut nonce = [0u8; 32];
                if payload.nonce.len() != 32 {
                    return Err(TecdsaError::Other("invalid nonce length".into()));
                }
                nonce.copy_from_slice(&payload.nonce);

                let dlog_proof = payload.dlog_proof.to_proof()?;

                self.r2_bcasts.insert(
                    from,
                    R2ReceivedBcast {
                        nonce,
                        vss_commitments,
                        dlog_proof,
                    },
                );

                self.check_r2_complete()?;
            }

            Llz25KeygenMsg::Round2Share(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Share in round {}",
                        self.round
                    )));
                }
                if self.r2_shares.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid share length".into()));
                }
                let mut fb = k256::FieldBytes::default();
                fb.copy_from_slice(&data);
                let share_val = Option::from(k256::Scalar::from_repr(fb))
                    .ok_or_else(|| TecdsaError::Other("invalid scalar in share".into()))?;
                self.r2_shares.insert(from, share_val);

                self.check_r2_complete()?;
            }

            Llz25KeygenMsg::Round3(data) => {
                if self.round != 3 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round3 in round {}",
                        self.round
                    )));
                }
                if self.r3_data.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let (payload, _): (R3Payload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R3: {e}")))?;

                let x_i_point = proj_from_bytes(&payload.x_i_bytes)?;

                let proof = payload
                    .proof
                    .to_proof()
                    .map_err(|e| TecdsaError::Other(format!("proof deser: {e}")))?;

                self.r3_data.insert(
                    from,
                    R3ReceivedData {
                        x_i_point,
                        pe_x_c1: payload.pe_x_c1,
                        pe_x_c2: payload.pe_x_c2,
                        proof,
                    },
                );

                if self.r3_data.len() == self.n() {
                    self.finalize()?;
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

    fn finish(mut self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .take()
            .ok_or_else(|| TecdsaError::Other("keygen not complete".into()))
    }

    fn current_round(&self) -> u16 {
        self.round
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_protocol::PartyId;

    use super::*;

    fn route_messages(machines: &mut [Llz25KeygenMachine]) -> bool {
        let mut pending: Vec<(PartyId, Outgoing<Llz25KeygenMsg>)> = Vec::new();
        for (idx, machine) in machines.iter_mut().enumerate() {
            let party_id = PartyId(idx as u16 + 1);
            for out in machine.drain_outgoing() {
                pending.push((party_id, out));
            }
        }

        for (from, outgoing) in pending {
            match outgoing.to {
                Recipient::Broadcast => {
                    for (idx, machine) in machines.iter_mut().enumerate() {
                        let recipient_id = PartyId(idx as u16 + 1);
                        if recipient_id == from {
                            continue;
                        }
                        machine
                            .handle(from, outgoing.msg.clone())
                            .unwrap_or_else(|e| {
                                panic!(
                                    "handle broadcast from {} to {} failed: {e}",
                                    from, recipient_id
                                )
                            });
                    }
                }
                Recipient::Party(to) => {
                    let to_idx = (to.0 - 1) as usize;
                    machines[to_idx]
                        .handle(from, outgoing.msg.clone())
                        .unwrap_or_else(|e| {
                            panic!("handle P2P from {} to {} failed: {e}", from, to)
                        });
                }
            }
        }

        machines.iter().all(|m| m.is_done())
    }

    #[test]
    #[ignore]
    fn keygen_interactive_3_parties() {
        let seed = "44444";
        let n = 3u16;
        let t = 2u16;
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let mut setup = ClSetup::new_secp256k1(seed).expect("CL setup");
        let (_sk_crs, pk_crs) = setup.keygen().expect("CRS keygen");

        let pk_qfi = &pk_crs.elt();

        let mut machines: Vec<Llz25KeygenMachine> = (0..n)
            .map(|i| {
                let pk_i = setup.pk_from_qfi(pk_qfi).expect("pk_from_qfi");
                Llz25KeygenMachine::new(
                    all_parties[i as usize],
                    all_parties.clone(),
                    t,
                    seed,
                    false,
                    pk_i,
                )
                .expect("Llz25KeygenMachine::new")
            })
            .collect();

        let max_rounds = 20;
        for round in 0..max_rounds {
            if route_messages(&mut machines) {
                println!("LLZ25 interactive DKG completed after {round} routing iterations");
                break;
            }
            assert!(
                round < max_rounds - 1,
                "DKG did not complete within {max_rounds} routing iterations"
            );
        }

        assert!(
            machines.iter().all(|m| m.is_done()),
            "not all machines completed"
        );

        let key_shares: Vec<Llz25KeyShare> = machines
            .into_iter()
            .map(|m| m.finish().expect("finish"))
            .collect();

        let public_key = key_shares[0].public_key;
        for (i, ks) in key_shares.iter().enumerate() {
            assert_eq!(
                ks.public_key,
                public_key,
                "party {} has different public key",
                i + 1
            );
        }

        for ks in &key_shares {
            let expected_x_i =
                <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
                    * ks.secret_share;
            let actual_x_i = ks.public_shares[(ks.party_index - 1) as usize];
            assert_eq!(
                actual_x_i, expected_x_i,
                "X_{} != x_{} * G",
                ks.party_index, ks.party_index
            );
        }

        for (i, ks) in key_shares.iter().enumerate() {
            assert_eq!(
                ks.public_shares,
                key_shares[0].public_shares,
                "party {} has different public_shares",
                i + 1
            );
        }

        for ks in &key_shares {
            let (c1, c2) = &ks.pe_x_components;
            assert!(
                !c1.is_empty(),
                "pe_x c1 is empty for party {}",
                ks.party_index
            );
            assert!(
                !c2.is_empty(),
                "pe_x c2 is empty for party {}",
                ks.party_index
            );
        }

        for ks in &key_shares {
            assert!(
                !ks.st_x_bytes.is_empty(),
                "st_x_bytes is empty for party {}",
                ks.party_index
            );
        }

        for ks in &key_shares {
            assert_eq!(ks.threshold, t);
            assert_eq!(ks.total, n);
        }

        println!(
            "LLZ25 interactive DKG OK: n={n}, t={t}, pk={:?}",
            public_key
        );
    }
}
