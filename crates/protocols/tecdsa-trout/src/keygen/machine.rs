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

//! StateMachine implementation for Trout interactive DKG.

use std::collections::BTreeMap;

use elliptic_curve::PrimeField;
use rand::RngCore;
use tecdsa_class_group::cl::ClSetup;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_evrf::{EvrfPublicKey, EvrfSecretKey};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
use zeroize::Zeroize;

use super::{
    msg::TroutKeygenMsg,
    rounds::{
        compute_commitment, proj_from_bytes, proj_to_bytes, scalar_to_bytes, R1LocalState,
        R2BcastPayload, R2ReceivedBcast, R3Payload, R3ReceivedData, SerDlogProof, SerQfi,
    },
};
use crate::{error::qfi_to_abc, key_share::TroutKeyShare};

// ---------------------------------------------------------------------------
// TroutKeygenMachine
// ---------------------------------------------------------------------------

/// StateMachine for the Trout 3-round interactive DKG (Protocol 3.1).
///
/// On construction, Round 1 logic executes immediately and a 32-byte hash
/// commitment is queued for broadcast.  Subsequent rounds are driven by
/// `handle` as messages arrive from other parties.
pub struct TroutKeygenMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    threshold: u16,
    setup: ClSetup,
    cl_setup_seed: String,
    use_128bit: bool,
    round: u16,

    r1_state: Option<R1LocalState>,
    r1_commitments: BTreeMap<PartyId, [u8; 32]>,

    r2_bcasts: BTreeMap<PartyId, R2ReceivedBcast>,
    r2_shares: BTreeMap<PartyId, k256::Scalar>,

    r3_data: BTreeMap<PartyId, R3ReceivedData>,

    // Intermediate values computed during R2->R3 transition, consumed during finalize.
    stash_combined_share: Option<k256::Scalar>,
    stash_delta_i: Option<Vec<u8>>,
    stash_public_key: Option<k256::ProjectivePoint>,
    stash_public_shares: Option<Vec<k256::ProjectivePoint>>,
    stash_cl_pk_abc: Option<(String, String, String)>,
    stash_my_ct_components: Option<(String, String, String, String, String, String)>,

    outgoing: Vec<Outgoing<TroutKeygenMsg>>,
    output: Option<TroutKeyShare>,
    done: bool,
}

impl Drop for TroutKeygenMachine {
    fn drop(&mut self) {
        if let Some(ref mut r1) = self.r1_state {
            r1.zeroize_secrets();
        }
        if let Some(ref mut s) = self.stash_combined_share {
            s.zeroize();
        }
        if let Some(ref mut s) = self.stash_delta_i {
            s.zeroize();
        }
        for share in self.r2_shares.values_mut() {
            share.zeroize();
        }
    }
}

impl TroutKeygenMachine {
    /// Create a new Trout DKG state machine from a pre-built `ClSetup`.
    ///
    /// This avoids recreating the expensive CL setup per party,
    /// which is useful in benchmarks where all parties share the same
    /// discriminant parameters.
    ///
    /// See [`Self::new`] for the full documentation.
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit: bool,
        mut setup: ClSetup,
    ) -> tecdsa_core::Result<Self> {
        // Generate the per-party long-term key material (eVRF keypair + CL public
        // contribution), then delegate. Benches time this (n,t)-independent keygen
        // separately (see `setup_benchmarks`) and call `new_with_key_material` so
        // DKG measures only the interactive sharing.
        let mut rng = rand::rngs::OsRng;
        let (evrf_sk, evrf_pk) = EvrfSecretKey::<k256::Secp256k1>::generate(&mut rng);
        let (_cl_sk_i, cl_pk_i) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("CL keygen failed: {e}")))?;
        Self::new_with_key_material(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit,
            setup,
            evrf_sk,
            evrf_pk,
            cl_pk_i,
        )
    }

    /// Like [`new_with_setup`](Self::new_with_setup) but reuses pre-generated
    /// per-party key material (eVRF keypair + CL public contribution) instead of
    /// generating it inside the constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_key_material(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit: bool,
        setup: ClSetup,
        evrf_sk: tecdsa_evrf::EvrfSecretKey<k256::Secp256k1>,
        evrf_pk: tecdsa_evrf::EvrfPublicKey<k256::Secp256k1>,
        cl_pk_i: tecdsa_class_group::cl::PublicKey,
    ) -> tecdsa_core::Result<Self> {
        if !all_parties.contains(&my_id) {
            return Err(TecdsaError::Other("my_id not in all_parties".into()));
        }

        let n = all_parties.len() as u16;

        let mut rng = rand::rngs::OsRng;

        let y_i = cl_pk_i.elt();
        let cl_contribution_abc =
            qfi_to_abc(y_i).map_err(|e| TecdsaError::Other(format!("{e}")))?;

        // 3. Feldman VSS
        let x_i = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let (vss_shares, vss_commitments) =
            tecdsa_vss::feldman::split::<k256::Secp256k1>(&x_i, threshold, n, &mut rng);

        // 4. DlogProof for A_{i,0} = x_i * G
        let a_i_0 = vss_commitments[0];
        let ephemeral = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let dlog_proof = tecdsa_curve::zk::dlog::DlogProof::<k256::Secp256k1>::prove(
            &x_i,
            &ephemeral,
            &a_i_0,
            b"trout-dkg-dlog",
        );

        // 5. Compute commitment
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let evrf_pk_bytes = <k256::Secp256k1 as TecdsaCurve>::point_to_bytes(&evrf_pk.point);
        let commitment = compute_commitment(
            &nonce,
            &evrf_pk_bytes,
            &vss_commitments,
            &cl_contribution_abc,
            &dlog_proof,
        );

        // Store our own R1 commitment
        let mut r1_commitments = BTreeMap::new();
        r1_commitments.insert(my_id, commitment);

        // Queue R1 broadcast
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: TroutKeygenMsg::Round1(commitment.to_vec()),
        }];

        let r1_local = R1LocalState {
            evrf_sk,
            evrf_pk,
            cl_contribution_abc,
            x_i,
            vss_shares,
            vss_commitments,
            dlog_proof,
            nonce,
            commitment,
        };

        Ok(Self {
            my_id,
            all_parties,
            threshold,
            setup,
            cl_setup_seed: cl_setup_seed.to_string(),
            use_128bit,
            round: 1,
            r1_state: Some(r1_local),
            r1_commitments,
            r2_bcasts: BTreeMap::new(),
            r2_shares: BTreeMap::new(),
            r3_data: BTreeMap::new(),
            stash_combined_share: None,
            stash_delta_i: None,
            stash_public_key: None,
            stash_public_shares: None,
            stash_cl_pk_abc: None,
            stash_my_ct_components: None,
            outgoing,
            output: None,
            done: false,
        })
    }

    /// Create a new Trout DKG state machine.
    ///
    /// Immediately executes Round 1 logic:
    /// - Generate eVRF keypair
    /// - Generate CL key contribution
    /// - Run Feldman VSS on a random secret
    /// - Prove DLog for the constant coefficient
    /// - Hash-commit to all public data
    /// - Queue the commitment for broadcast
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit: bool,
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
            setup,
        )
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

    // -----------------------------------------------------------------------
    // Round transitions
    // -----------------------------------------------------------------------

    /// Transition from R1 -> R2: broadcast decommitment and send P2P shares.
    fn transition_to_r2(&mut self) -> tecdsa_core::Result<()> {
        let r1 = self
            .r1_state
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("r1_state missing".into()))?;

        let evrf_pk_bytes = <k256::Secp256k1 as TecdsaCurve>::point_to_bytes(&r1.evrf_pk.point);
        let vss_com_bytes: Vec<Vec<u8>> = r1.vss_commitments.iter().map(proj_to_bytes).collect();

        let r2_payload = R2BcastPayload {
            nonce: r1.nonce.to_vec(),
            evrf_pk_bytes,
            vss_commitment_points: vss_com_bytes,
            cl_contribution_abc: SerQfi::from_abc(&r1.cl_contribution_abc),
            dlog_proof: SerDlogProof::from_proof(&r1.dlog_proof),
        };

        let r2_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2 bcast: {e}")))?;

        // Store our own R2 bcast
        self.r2_bcasts.insert(
            self.my_id,
            R2ReceivedBcast {
                nonce: r1.nonce,
                evrf_pk: r1.evrf_pk.clone(),
                vss_commitments: r1.vss_commitments.clone(),
                cl_contribution_abc: r1.cl_contribution_abc.clone(),
                dlog_proof: r1.dlog_proof.clone(),
            },
        );

        // Store our own VSS share to self
        let my_1based = self.my_1based_index();
        let my_share_value = r1
            .vss_shares
            .iter()
            .find(|s| s.index == my_1based)
            .expect("own share must exist")
            .value;
        self.r2_shares.insert(self.my_id, my_share_value);

        // Broadcast R2
        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: TroutKeygenMsg::Round2Bcast(r2_bytes),
        });

        // P2P: send VSS share s_{my, j} to each party j
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
            let share_bytes = scalar_to_bytes(&share_for_j.value);
            self.outgoing.push(Outgoing {
                to: Recipient::Party(party),
                msg: TroutKeygenMsg::Round2Share(share_bytes),
            });
        }

        self.round = 2;
        Ok(())
    }

    /// Transition from R2 -> R3: delegates to rounds::transition_to_r3.
    fn transition_to_r3(&mut self) -> tecdsa_core::Result<()> {
        let my_1based = self.my_1based_index();

        let (
            combined_share,
            delta_i,
            public_key,
            public_shares,
            cl_pk_abc,
            my_ct_components,
            r3_bytes,
        ) = super::rounds::transition_to_r3(
            self.my_id,
            &self.all_parties,
            my_1based,
            &self.r1_commitments,
            &self.r2_bcasts,
            &self.r2_shares,
            &mut self.setup,
            &mut self.r3_data,
        )?;

        // Broadcast R3
        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: TroutKeygenMsg::Round3(r3_bytes),
        });

        // Stash intermediate values for finalize
        self.stash_combined_share = Some(combined_share);
        self.stash_delta_i = Some(delta_i);
        self.stash_public_key = Some(public_key);
        self.stash_public_shares = Some(public_shares);
        self.stash_cl_pk_abc = Some(cl_pk_abc);
        self.stash_my_ct_components = Some(my_ct_components);

        self.round = 3;
        Ok(())
    }

    /// Finalize: verify all R3 proofs and construct TroutKeyShare.
    fn finalize(&mut self) -> tecdsa_core::Result<()> {
        let r1_state = self
            .r1_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r1_state missing in finalize".into()))?;

        let combined_share = self
            .stash_combined_share
            .take()
            .ok_or_else(|| TecdsaError::Other("combined_share missing".into()))?;
        let delta_i = self
            .stash_delta_i
            .take()
            .ok_or_else(|| TecdsaError::Other("delta_i missing".into()))?;
        let public_key = self
            .stash_public_key
            .take()
            .ok_or_else(|| TecdsaError::Other("public_key missing".into()))?;
        let public_shares = self
            .stash_public_shares
            .take()
            .ok_or_else(|| TecdsaError::Other("public_shares missing".into()))?;
        let cl_pk_abc = self
            .stash_cl_pk_abc
            .take()
            .ok_or_else(|| TecdsaError::Other("cl_pk_abc missing".into()))?;
        let my_ct_components = self
            .stash_my_ct_components
            .take()
            .ok_or_else(|| TecdsaError::Other("my_ct_components missing".into()))?;

        let key_share = super::rounds::finalize(
            self.my_id,
            &self.all_parties,
            self.my_1based_index(),
            &self.r3_data,
            &self.r2_bcasts,
            r1_state,
            &mut self.setup,
            combined_share,
            delta_i,
            public_key,
            &public_shares,
            cl_pk_abc,
            my_ct_components,
            &self.cl_setup_seed,
            self.use_128bit,
            self.threshold,
        )?;

        self.output = Some(key_share);
        self.done = true;
        Ok(())
    }

    /// Check whether all R2 broadcasts and P2P shares have been received.
    fn check_r2_complete(&mut self) -> tecdsa_core::Result<()> {
        if self.r2_bcasts.len() == self.n() && self.r2_shares.len() == self.n() {
            self.transition_to_r3()?;
        }
        Ok(())
    }
}

impl StateMachine for TroutKeygenMachine {
    type Output = TroutKeyShare;
    type Inbound = TroutKeygenMsg;
    type Outbound = TroutKeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        match msg {
            TroutKeygenMsg::Round1(data) => {
                if self.round != 1 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round1 in round {}",
                        self.round
                    )));
                }
                if self.r1_commitments.contains_key(&from) {
                    return Err(TecdsaError::Other(format!("duplicate R1 from {from}")));
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

            TroutKeygenMsg::Round2Bcast(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Bcast in round {}",
                        self.round
                    )));
                }
                if self.r2_bcasts.contains_key(&from) {
                    return Err(TecdsaError::Other(format!("duplicate R2Bcast from {from}")));
                }

                let (payload, _): (R2BcastPayload, _) =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| TecdsaError::Other(format!("deser R2 bcast: {e}")))?;

                let evrf_pk_point =
                    <k256::Secp256k1 as TecdsaCurve>::point_from_bytes(&payload.evrf_pk_bytes)
                        .map_err(|_| TecdsaError::Other("invalid eVRF pk point".into()))?;
                let evrf_pk = EvrfPublicKey {
                    point: evrf_pk_point,
                };

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
                        evrf_pk,
                        vss_commitments,
                        cl_contribution_abc: payload.cl_contribution_abc.to_abc(),
                        dlog_proof,
                    },
                );

                self.check_r2_complete()?;
            }

            TroutKeygenMsg::Round2Share(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2Share in round {}",
                        self.round
                    )));
                }
                if self.r2_shares.contains_key(&from) {
                    return Err(TecdsaError::Other(format!("duplicate R2Share from {from}")));
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

            TroutKeygenMsg::Round3(data) => {
                if self.round != 3 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round3 in round {}",
                        self.round
                    )));
                }
                if self.r3_data.contains_key(&from) {
                    return Err(TecdsaError::Other(format!("duplicate R3 from {from}")));
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
                        ct_components: (
                            payload.ct_c1_abc.a.clone(),
                            payload.ct_c1_abc.b.clone(),
                            payload.ct_c1_abc.c.clone(),
                            payload.ct_c2_abc.a.clone(),
                            payload.ct_c2_abc.b.clone(),
                            payload.ct_c2_abc.c.clone(),
                        ),
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

    /// Helper: route all outgoing messages from all machines to their recipients.
    /// Returns true if all machines are done.
    fn route_messages(machines: &mut [TroutKeygenMachine]) -> bool {
        // Collect all outgoing messages from all parties.
        let mut pending: Vec<(PartyId, Outgoing<TroutKeygenMsg>)> = Vec::new();
        for (idx, machine) in machines.iter_mut().enumerate() {
            let party_id = PartyId(idx as u16 + 1);
            for out in machine.drain_outgoing() {
                pending.push((party_id, out));
            }
        }

        // Deliver each message to its recipient(s).
        for (from, outgoing) in pending {
            match outgoing.to {
                Recipient::Broadcast => {
                    for (idx, machine) in machines.iter_mut().enumerate() {
                        let recipient_id = PartyId(idx as u16 + 1);
                        if recipient_id == from {
                            continue; // skip self-delivery
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

    /// Interactive 3-round DKG for 3 parties (n=3, t=2).
    ///
    /// Verifies:
    /// - All parties produce valid `TroutKeyShare`.
    /// - All parties agree on the same public key.
    /// - Public verification shares satisfy X_i = x_i * G.
    #[test]
    #[ignore] // CL operations are slow (~30-60s in debug mode)
    fn keygen_interactive_3_parties() {
        let seed = "33333";
        let n = 3u16;
        let t = 2u16; // reconstruction threshold: 2 parties needed to sign
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        // Create machines (Round 1 executes immediately in the constructor).
        let mut machines: Vec<TroutKeygenMachine> = (0..n)
            .map(|i| {
                TroutKeygenMachine::new(
                    all_parties[i as usize],
                    all_parties.clone(),
                    t,
                    seed,
                    false, // use_128bit = false for fast testing
                )
                .expect("TroutKeygenMachine::new")
            })
            .collect();

        // Drive the protocol through rounds until all machines are done.
        let max_rounds = 20;
        for round in 0..max_rounds {
            if route_messages(&mut machines) {
                println!("Trout interactive DKG completed after {round} routing iterations");
                break;
            }
            assert!(
                round < max_rounds - 1,
                "DKG did not complete within {max_rounds} routing iterations"
            );
        }

        // All machines should be done.
        assert!(
            machines.iter().all(|m| m.is_done()),
            "not all machines completed"
        );

        // Extract key shares.
        let key_shares: Vec<TroutKeyShare> = machines
            .into_iter()
            .map(|m| m.finish().expect("finish"))
            .collect();

        // 1. Verify all parties agree on the same public key.
        let public_key = key_shares[0].public_key;
        for (i, ks) in key_shares.iter().enumerate() {
            assert_eq!(
                ks.public_key,
                public_key,
                "party {} has different public key",
                i + 1
            );
        }

        // 2. Verify public verification shares are consistent: X_i = x_i * G.
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

        // 3. Verify all parties have the same public_shares vector.
        for (i, ks) in key_shares.iter().enumerate() {
            assert_eq!(
                ks.public_shares,
                key_shares[0].public_shares,
                "party {} has different public_shares",
                i + 1
            );
        }

        // 4. Verify threshold and total.
        for ks in &key_shares {
            assert_eq!(ks.threshold, t);
            assert_eq!(ks.total, n);
        }

        println!(
            "Trout interactive DKG OK: n={n}, t={t}, pk={:?}",
            public_key
        );
    }
}
