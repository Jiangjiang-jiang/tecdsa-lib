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

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand::RngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_joye_libert::{kgen::JlPublicKey, zk::zkjlmod::ZkJlModProof};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{
    msg::Xal23KeygenMsg,
    rounds::{
        compute_commitment, proj_from_bytes, proj_to_bytes, scalar_from_bytes, scalar_to_bytes,
        R1LocalState, R2BcastPayload, R2ReceivedBcast, SerDlogProof,
    },
};
use crate::key_share::Xal23KeyShare;

pub struct Xal23KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    #[allow(dead_code)]
    jl_p_bits: u64,
    #[allow(dead_code)]
    jl_k: u32,
    round: u16,

    r1_state: Option<R1LocalState<C>>,
    r1_commitments: BTreeMap<PartyId, [u8; 32]>,

    r2_bcasts: BTreeMap<PartyId, R2ReceivedBcast<C>>,
    r2_shares: BTreeMap<PartyId, C::Scalar>,

    outgoing: Vec<Outgoing<Xal23KeygenMsg>>,
    output: Option<Xal23KeyShare<C>>,
    done: bool,
}

impl<C: TecdsaCurve> Drop for Xal23KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for share in self.r2_shares.values_mut() {
            share.zeroize();
        }
    }
}

impl<C: TecdsaCurve> Xal23KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        jl_p_bits: u64,
        jl_k: u32,
    ) -> tecdsa_core::Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let (jl_pk, jl_sk, jl_qnr) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(jl_p_bits, jl_k, &mut rng);
        Self::new_with_jl_keypair(
            my_id,
            all_parties,
            threshold,
            jl_pk,
            jl_sk,
            jl_qnr,
            jl_p_bits,
            jl_k,
        )
    }

    pub fn new_with_jl_keypair(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        jl_pk: tecdsa_joye_libert::JlPublicKey,
        jl_sk: tecdsa_joye_libert::JlSecretKey,
        jl_qnr: rug::Integer,
        jl_p_bits: u64,
        jl_k: u32,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }
        if all_parties.len() < 2 {
            return Err(TecdsaError::Other("need at least 2 parties".into()));
        }
        if threshold < 2 {
            return Err(TecdsaError::Other("threshold must be >= 2".into()));
        }
        if threshold > all_parties.len() as u16 {
            return Err(TecdsaError::Other("threshold must be <= n".into()));
        }

        let n = all_parties.len() as u16;
        let mut rng = rand::rngs::OsRng;

        let jl_mod_proof = ZkJlModProof::prove(&jl_pk, &jl_sk, &jl_qnr, &mut rng);

        let x_i = C::random_scalar(&mut rng);
        let (vss_shares, vss_commitments) =
            tecdsa_vss::feldman::split::<C>(&x_i, threshold, n, &mut rng);

        let a_i_0 = vss_commitments[0];
        let ephemeral = C::random_scalar(&mut rng);
        let dlog_proof = tecdsa_curve::zk::dlog::DlogProof::<C>::prove(
            &x_i,
            &ephemeral,
            &a_i_0,
            b"xal23-dkg-dlog",
        );

        let jl_pk_json = bincode::serde::encode_to_vec(&jl_pk, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize JL pk: {e}")))?;

        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let jl_mod_proof_json =
            bincode::serde::encode_to_vec(&jl_mod_proof, bincode::config::standard())
                .map_err(|e| TecdsaError::Other(format!("serialize JL mod proof: {e}")))?;

        let commitment = compute_commitment::<C>(
            &nonce,
            &jl_pk_json,
            &vss_commitments,
            &dlog_proof,
            &jl_mod_proof_json,
        );

        let mut r1_commitments = BTreeMap::new();
        r1_commitments.insert(my_id, commitment);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Xal23KeygenMsg::Round1(commitment.to_vec()),
        }];

        let r1_local = R1LocalState {
            jl_sk: Some(jl_sk),
            jl_pk,
            x_i,
            vss_shares,
            vss_commitments,
            dlog_proof,
            jl_mod_proof,
            nonce,
        };

        Ok(Self {
            my_id,
            all_parties,
            threshold,
            jl_p_bits,
            jl_k,
            round: 1,
            r1_state: Some(r1_local),
            r1_commitments,
            r2_bcasts: BTreeMap::new(),
            r2_shares: BTreeMap::new(),
            outgoing,
            output: None,
            done: false,
        })
    }

    fn n(&self) -> usize {
        self.all_parties.len()
    }

    fn my_1based_index(&self) -> u16 {
        self.all_parties
            .iter()
            .position(|p| *p == self.my_id)
            .expect("my_id must be in all_parties") as u16
            + 1
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

        let jl_pk_json = bincode::serde::encode_to_vec(&r1.jl_pk, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize JL pk: {e}")))?;

        let vss_com_bytes: Vec<Vec<u8>> =
            r1.vss_commitments.iter().map(proj_to_bytes::<C>).collect();

        let r2_payload = R2BcastPayload {
            nonce: r1.nonce.to_vec(),
            jl_pk_json: jl_pk_json.clone(),
            vss_commitment_points: vss_com_bytes,
            dlog_proof: SerDlogProof::from_proof::<C>(&r1.dlog_proof),
            jl_mod_proof: r1.jl_mod_proof.clone(),
        };

        let r2_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2 bcast: {e}")))?;

        self.r2_bcasts.insert(
            self.my_id,
            R2ReceivedBcast {
                nonce: r1.nonce,
                jl_pk: r1.jl_pk.clone(),
                vss_commitments: r1.vss_commitments.clone(),
                dlog_proof: r1.dlog_proof.clone(),
                jl_mod_proof: r1.jl_mod_proof.clone(),
            },
        );

        let my_1based = self.my_1based_index();
        let my_share_value = r1
            .vss_shares
            .iter()
            .find(|s| s.index == my_1based)
            .expect("own share must exist")
            .value;
        self.r2_shares.insert(self.my_id, my_share_value);

        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Xal23KeygenMsg::Round2Bcast(r2_bytes),
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
                .expect("share for party j must exist");
            let share_bytes = scalar_to_bytes::<C>(&share_for_j.value);
            self.outgoing.push(Outgoing {
                to: Recipient::Party(party),
                msg: Xal23KeygenMsg::Round2Share(share_bytes),
            });
        }

        self.round = 2;
        Ok(())
    }

    fn finalize(&mut self) -> tecdsa_core::Result<()> {
        let mut r1_state = self
            .r1_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r1_state missing in finalize".into()))?;

        let my_1based = self.my_1based_index();

        let key_share = super::rounds::finalize::<C>(
            self.my_id,
            &self.all_parties,
            my_1based,
            self.threshold,
            &self.r1_commitments,
            &self.r2_bcasts,
            &self.r2_shares,
            &mut r1_state,
        )?;

        self.output = Some(key_share);
        self.done = true;
        Ok(())
    }

    fn check_r2_complete(&mut self) -> tecdsa_core::Result<()> {
        if self.r2_bcasts.len() == self.n() && self.r2_shares.len() == self.n() {
            self.finalize()?;
        }
        Ok(())
    }
}

impl<C: TecdsaCurve> StateMachine for Xal23KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Xal23KeyShare<C>;
    type Inbound = Xal23KeygenMsg;
    type Outbound = Xal23KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("cannot handle message from self".into()));
        }
        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        match msg {
            Xal23KeygenMsg::Round1(data) => {
                if self.round != 1 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round1 in round {}",
                        self.round
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid R1 commitment length".into()));
                }
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&data);
                if self.r1_commitments.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate Round1 message from {from}"
                    )));
                }
                self.r1_commitments.insert(from, commitment);

                if self.r1_commitments.len() == self.n() {
                    self.transition_to_r2()?;
                }
            }

            Xal23KeygenMsg::Round2Bcast(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Bcast in round {}",
                        self.round
                    )));
                }

                let (payload, _): (R2BcastPayload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R2 bcast: {e}")))?;

                let (jl_pk, _): (JlPublicKey, _) = bincode::serde::decode_from_slice(
                    &payload.jl_pk_json,
                    bincode::config::standard(),
                )
                .map_err(|e| TecdsaError::Other(format!("deser JL pk: {e}")))?;

                let vss_commitments: Vec<C::ProjectivePoint> = payload
                    .vss_commitment_points
                    .iter()
                    .map(|bytes| proj_from_bytes::<C>(bytes))
                    .collect::<Result<Vec<_>, _>>()?;

                let mut nonce = [0u8; 32];
                if payload.nonce.len() != 32 {
                    return Err(TecdsaError::Other("invalid nonce length".into()));
                }
                nonce.copy_from_slice(&payload.nonce);

                let dlog_proof = payload.dlog_proof.to_proof::<C>()?;

                if self.r2_bcasts.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate Round2Bcast message from {from}"
                    )));
                }
                self.r2_bcasts.insert(
                    from,
                    R2ReceivedBcast {
                        nonce,
                        jl_pk,
                        vss_commitments,
                        dlog_proof,
                        jl_mod_proof: payload.jl_mod_proof,
                    },
                );

                self.check_r2_complete()?;
            }

            Xal23KeygenMsg::Round2Share(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Share in round {}",
                        self.round
                    )));
                }
                let share_val = scalar_from_bytes::<C>(&data)?;
                if self.r2_shares.contains_key(&from) {
                    return Err(TecdsaError::Other(format!(
                        "duplicate Round2Share message from {from}"
                    )));
                }
                self.r2_shares.insert(from, share_val);

                self.check_r2_complete()?;
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
    use tecdsa_protocol::state_machine::Outgoing;

    use super::*;

    type C = k256::Secp256k1;

    const TEST_JL_P_BITS: u64 = 256;
    const TEST_JL_K: u32 = 128;

    fn run_dkg(n: u16, t: u16) -> Vec<Xal23KeyShare<C>> {
        let parties: Vec<PartyId> = (0..n).map(PartyId).collect();

        let mut machines: Vec<Xal23KeygenMachine<C>> = parties
            .iter()
            .map(|&pid| {
                Xal23KeygenMachine::new(pid, parties.clone(), t, TEST_JL_P_BITS, TEST_JL_K)
                    .expect("machine creation should succeed")
            })
            .collect();

        let mut r1_messages: Vec<(PartyId, Vec<Outgoing<Xal23KeygenMsg>>)> = Vec::new();
        for (i, machine) in machines.iter_mut().enumerate() {
            let msgs = machine.drain_outgoing();
            r1_messages.push((parties[i], msgs));
        }

        for (sender, msgs) in &r1_messages {
            for outgoing in msgs {
                match &outgoing.to {
                    Recipient::Broadcast => {
                        for (j, machine) in machines.iter_mut().enumerate() {
                            if parties[j] != *sender {
                                machine
                                    .handle(*sender, outgoing.msg.clone())
                                    .expect("R1 handle should succeed");
                            }
                        }
                    }
                    Recipient::Party(target) => {
                        let idx = parties.iter().position(|p| p == target).unwrap();
                        machines[idx]
                            .handle(*sender, outgoing.msg.clone())
                            .expect("R1 P2P handle should succeed");
                    }
                }
            }
        }

        let mut r2_messages: Vec<(PartyId, Vec<Outgoing<Xal23KeygenMsg>>)> = Vec::new();
        for (i, machine) in machines.iter_mut().enumerate() {
            let msgs = machine.drain_outgoing();
            r2_messages.push((parties[i], msgs));
        }

        for (sender, msgs) in &r2_messages {
            for outgoing in msgs {
                match &outgoing.to {
                    Recipient::Broadcast => {
                        for (j, machine) in machines.iter_mut().enumerate() {
                            if parties[j] != *sender {
                                machine
                                    .handle(*sender, outgoing.msg.clone())
                                    .expect("R2 bcast handle should succeed");
                            }
                        }
                    }
                    Recipient::Party(target) => {
                        let idx = parties.iter().position(|p| p == target).unwrap();
                        machines[idx]
                            .handle(*sender, outgoing.msg.clone())
                            .expect("R2 P2P handle should succeed");
                    }
                }
            }
        }

        for machine in &machines {
            assert!(machine.is_done(), "machine should be done after R2");
        }

        machines
            .into_iter()
            .map(|m| m.finish().expect("finish should succeed"))
            .collect()
    }

    #[test]
    fn dkg_n2_t2_produces_consistent_shares() {
        let shares = run_dkg(2, 2);

        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[0].party_index, 0);
        assert_eq!(shares[1].party_index, 1);
        assert_eq!(shares[0].jl_pks.len(), 2);
        assert_eq!(shares[1].jl_pks.len(), 2);
        assert_eq!(shares[0].jl_pks[0].n, shares[1].jl_pks[0].n);
        assert_eq!(shares[0].jl_pks[1].n, shares[1].jl_pks[1].n);

        for (i, share) in shares.iter().enumerate() {
            let expected = k256::ProjectivePoint::GENERATOR * share.secret_share;
            assert_eq!(
                share.public_shares[i], expected,
                "public share mismatch for party {i}"
            );
        }

        let vss_shares = vec![
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 1,
                value: shares[0].secret_share,
            },
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 2,
                value: shares[1].secret_share,
            },
        ];
        let reconstructed_x = tecdsa_vss::shamir::reconstruct::<k256::Secp256k1>(&vss_shares);
        let reconstructed_pk = k256::ProjectivePoint::GENERATOR * reconstructed_x;
        assert_eq!(
            reconstructed_pk, shares[0].public_key,
            "reconstructed PK should match"
        );
    }

    #[test]
    fn dkg_n3_t2_produces_consistent_shares() {
        let shares = run_dkg(3, 2);

        assert_eq!(shares.len(), 3);

        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[1].public_key, shares[2].public_key);

        assert_eq!(shares[0].party_index, 0);
        assert_eq!(shares[1].party_index, 1);
        assert_eq!(shares[2].party_index, 2);

        for share in &shares {
            assert_eq!(share.jl_pks.len(), 3);
        }

        let any_two = vec![
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 1,
                value: shares[0].secret_share,
            },
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 3,
                value: shares[2].secret_share,
            },
        ];
        let reconstructed_x = tecdsa_vss::shamir::reconstruct::<k256::Secp256k1>(&any_two);
        let reconstructed_pk = k256::ProjectivePoint::GENERATOR * reconstructed_x;
        assert_eq!(
            reconstructed_pk, shares[0].public_key,
            "any 2-of-3 should reconstruct the same public key"
        );
    }

    #[test]
    fn dkg_n3_t2_threshold_reconstruction() {
        let shares = run_dkg(3, 3);

        assert_eq!(shares.len(), 3);

        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[1].public_key, shares[2].public_key);

        let all_three = vec![
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 1,
                value: shares[0].secret_share,
            },
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 2,
                value: shares[1].secret_share,
            },
            tecdsa_vss::shamir::Share::<k256::Secp256k1> {
                index: 3,
                value: shares[2].secret_share,
            },
        ];
        let reconstructed_x = tecdsa_vss::shamir::reconstruct::<k256::Secp256k1>(&all_three);
        let reconstructed_pk = k256::ProjectivePoint::GENERATOR * reconstructed_x;
        assert_eq!(
            reconstructed_pk, shares[0].public_key,
            "3-of-3 should reconstruct the same public key"
        );
    }
}
