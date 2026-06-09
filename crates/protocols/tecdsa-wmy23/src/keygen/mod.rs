// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 threshold key generation protocol (DRG-based, paper-compliant).
//!
//! Implements TKeygen from WMY23 (Wang, Mei, Yu. "Real Threshold ECDSA."
//! NDSS 2023, Figure 3) using the DRG primitive.
//!
//! ## Protocol Rounds
//!
//! 1. **Commitment:** CL keygen + R_Key + DRG.Gen → broadcast commitment.
//! 2. **Decommit + shares:** decommit (Pedersen commitments, CL pk, R_Key
//!    proof, CL ciphertext, R_Enc-PC proof) + P2P Pedersen VSS shares.
//! 3. **Combine:** DRG.Comb + RevealExp → broadcast combine output.
//! 4. **Finalize:** CombVf + ExpVf → compute key share.

pub mod msg;
pub mod rounds;

use elliptic_curve::PrimeField;
use msg::Wmy23KeygenMsg;
use rounds::{
    KeygenR1Bcast, KeygenR1State, KeygenR2Bcast, KeygenR3Bcast, KeygenR3State, VerifiedR2,
};
use tecdsa_class_group::drg::PedersenVssShare;
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use crate::key_share::Wmy23KeyShare;

/// WMY23 key generation state machine (DRG-based).
pub struct Wmy23KeygenMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    _threshold: u16,
    setup: tecdsa_class_group::cl::ClSetup,
    r1_state: Option<KeygenR1State>,
    // Round 1: collected commitments
    r1_bcasts: Vec<Option<KeygenR1Bcast>>,
    // Round 2: collected decommitments and P2P shares
    r2_bcasts: Vec<Option<KeygenR2Bcast>>,
    r2_shares: Vec<Option<(k256::Scalar, k256::Scalar)>>,
    // Round 2 verification results (stored for Round 3)
    r2_verified: Vec<Option<VerifiedR2>>,
    // Round 3: collected combine broadcasts
    r3_bcasts: Vec<Option<KeygenR3Bcast>>,
    r3_state: Option<KeygenR3State>,
    outgoing: Vec<Outgoing<Wmy23KeygenMsg>>,
    round: u16,
    output: Option<Wmy23KeyShare>,
    done: bool,
}

impl Wmy23KeygenMachine {
    /// Create a new WMY23 keygen state machine from a pre-built `ClSetup`.
    ///
    /// This avoids recreating the expensive CL setup per party,
    /// which is useful in benchmarks where all parties share the same
    /// discriminant parameters.
    ///
    /// The `cl_setup_seed` and `use_128bit_security` parameters are still
    /// required because they are stored in the key share for later
    /// reconstruction.
    ///
    /// See [`Self::new`] for the full documentation.
    pub fn new_with_setup(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
        mut setup: tecdsa_class_group::cl::ClSetup,
    ) -> tecdsa_core::Result<Self> {
        // Generate the per-party long-term CL keypair, then delegate. Benches time
        // this (n,t)-independent keygen separately (see `setup_benchmarks`) and call
        // `new_with_keypair` so DKG measures only the interactive sharing.
        let (cl_sk, cl_pk) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("CL keygen failed: {e}")))?;
        Self::new_with_keypair(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit_security,
            setup,
            cl_sk,
            cl_pk,
        )
    }

    /// Like [`new_with_setup`](Self::new_with_setup) but reuses a pre-generated
    /// per-party CL keypair instead of generating it inside the constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_keypair(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
        mut setup: tecdsa_class_group::cl::ClSetup,
        cl_sk: tecdsa_class_group::cl::ClSecretKey,
        cl_pk: tecdsa_class_group::cl::ClPublicKey,
    ) -> tecdsa_core::Result<Self> {
        let n = all_parties.len();
        let my_idx = all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not found in all_parties".into()))?;

        let mut rng = rand::thread_rng();
        let (r1_state, r1_bcast) = rounds::keygen_round1(
            &mut setup,
            cl_setup_seed,
            my_idx,
            n as u16,
            threshold,
            use_128bit_security,
            cl_sk,
            cl_pk,
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("keygen_round1 failed: {e}")))?;

        let mut r1_bcasts: Vec<Option<KeygenR1Bcast>> = vec![None; n];
        r1_bcasts[my_idx] = Some(r1_bcast.clone());

        let mut outgoing = Vec::new();
        let commitment_bytes = r1_bcast.commitment.to_vec();
        outgoing.push(Outgoing {
            to: tecdsa_protocol::Recipient::Broadcast,
            msg: Wmy23KeygenMsg::Round1(commitment_bytes),
        });

        Ok(Self {
            my_id,
            all_parties,
            _threshold: threshold,
            setup,
            r1_state: Some(r1_state),
            r1_bcasts,
            r2_bcasts: vec![None; n],
            r2_shares: vec![None; n],
            r2_verified: vec![None; n],
            r3_bcasts: vec![None; n],
            r3_state: None,
            outgoing,
            round: 1,
            output: None,
            done: false,
        })
    }

    /// Create a new WMY23 keygen state machine.
    ///
    /// Runs keygen Round 1 (CL keygen + R_Key + DRG.Gen + commitment) and
    /// queues the commitment broadcast.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
    ) -> tecdsa_core::Result<Self> {
        let setup = if use_128bit_security {
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            tecdsa_class_group::cl::ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        Self::new_with_setup(
            my_id,
            all_parties,
            threshold,
            cl_setup_seed,
            use_128bit_security,
            setup,
        )
    }

    fn my_idx(&self) -> usize {
        self.all_parties
            .iter()
            .position(|p| *p == self.my_id)
            .expect("my_id must be in all_parties")
    }

    fn party_idx(&self, party: PartyId) -> Option<usize> {
        self.all_parties.iter().position(|p| *p == party)
    }

    fn all_r1_collected(&self) -> bool {
        self.r1_bcasts.iter().all(|b| b.is_some())
    }

    fn all_r2_collected(&self) -> bool {
        self.r2_bcasts.iter().all(|b| b.is_some()) && self.r2_shares.iter().all(|s| s.is_some())
    }

    fn all_r3_collected(&self) -> bool {
        self.r3_bcasts.iter().all(|b| b.is_some())
    }

    /// Transition from Round 1 to Round 2: emit decommit broadcast + P2P shares.
    fn transition_to_r2(&mut self) -> tecdsa_core::Result<()> {
        let r1_state = self
            .r1_state
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("r1_state missing".into()))?;

        let r2_bcast = rounds::keygen_round2_bcast(r1_state, &self.setup);
        let my_idx = self.my_idx();

        // Store own R2 broadcast and own share
        self.r2_bcasts[my_idx] = Some(r2_bcast.clone());
        let own_share = rounds::keygen_round2_share(r1_state, my_idx);
        self.r2_shares[my_idx] = Some(own_share);

        // Store own verified R2 data
        let own_coms = r1_state.drg_gen.commitments.clone();
        self.r2_verified[my_idx] = Some(VerifiedR2 {
            commitments: own_coms,
            cl_pk_abc: r1_state.cl_pk_abc.clone(),
        });

        // Emit R2 decommit as broadcast
        let payload = rounds::serialize_r2(&r2_bcast);
        self.outgoing.push(Outgoing {
            to: tecdsa_protocol::Recipient::Broadcast,
            msg: Wmy23KeygenMsg::Round2(payload),
        });

        // Emit P2P Pedersen VSS shares
        for party in self.all_parties.clone() {
            if party == self.my_id {
                continue;
            }
            let recipient_idx = self
                .party_idx(party)
                .ok_or_else(|| TecdsaError::Other("recipient not found".into()))?;
            let share = rounds::keygen_round2_share(r1_state, recipient_idx);
            let share_bytes = {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&share.0.to_repr() as &[u8]);
                buf.extend_from_slice(&share.1.to_repr());
                buf
            };
            self.outgoing.push(Outgoing {
                to: tecdsa_protocol::Recipient::Party(party),
                msg: Wmy23KeygenMsg::Round3(share_bytes),
            });
        }

        self.round = 2;
        Ok(())
    }

    /// Verify R2 broadcast from another party and store result.
    fn verify_and_store_r2(&mut self, from_idx: usize) -> tecdsa_core::Result<()> {
        let r1_bcast = self.r1_bcasts[from_idx]
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("missing R1 bcast".into()))?;
        let r2_bcast = self.r2_bcasts[from_idx]
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("missing R2 bcast".into()))?;
        let share_pair = self.r2_shares[from_idx]
            .ok_or_else(|| TecdsaError::Other("missing P2P share".into()))?;

        let my_index_1based = (self.my_idx() + 1) as u16;
        let my_share = PedersenVssShare {
            index: my_index_1based,
            value: share_pair.0,
            randomness: share_pair.1,
        };

        let verified = rounds::verify_r2(&self.setup, &r1_bcast.commitment, r2_bcast, &my_share)
            .map_err(|e| {
                TecdsaError::Other(format!("R2 verification failed for party {from_idx}: {e}"))
            })?;

        self.r2_verified[from_idx] = Some(verified);
        Ok(())
    }

    /// Transition from Round 2 to Round 3: verify all R2 data, run Comb + RevealExp.
    fn transition_to_r3(&mut self) -> tecdsa_core::Result<()> {
        let n = self.all_parties.len();
        let my_idx = self.my_idx();

        // Verify all other parties' R2 broadcasts
        for j in 0..n {
            if j == my_idx {
                continue;
            }
            self.verify_and_store_r2(j)?;
        }

        let r1_state = self
            .r1_state
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("r1_state missing".into()))?;

        // Collect shares and commitments for DRG.Comb
        let received_shares: Vec<(u16, PedersenVssShare)> = (0..n)
            .map(|j| {
                let sender_index = (j + 1) as u16;
                let my_index_1based = (my_idx + 1) as u16;
                let share_pair = self.r2_shares[j].expect("share should be present");
                (
                    sender_index,
                    PedersenVssShare {
                        index: my_index_1based,
                        value: share_pair.0,
                        randomness: share_pair.1,
                    },
                )
            })
            .collect();

        let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n)
            .map(|j| {
                let sender_index = (j + 1) as u16;
                let verified = self.r2_verified[j].as_ref().expect("verified data");
                (sender_index, verified.commitments.clone())
            })
            .collect();

        // Run DRG.Comb + RevealExp
        let (r3_state, r3_bcast) = rounds::keygen_round3_with_shares(
            &mut self.setup,
            &r1_state.cl_pk_abc,
            (my_idx + 1) as u16,
            &received_shares,
            &all_commitments,
        )
        .map_err(|e| TecdsaError::Other(format!("keygen_round3 failed: {e}")))?;

        // Store own R3
        self.r3_bcasts[my_idx] = Some(r3_bcast.clone());
        self.r3_state = Some(r3_state);

        // Emit R3 combine as broadcast
        let payload = rounds::serialize_r3(&r3_bcast);
        self.outgoing.push(Outgoing {
            to: tecdsa_protocol::Recipient::Broadcast,
            msg: Wmy23KeygenMsg::Round4(payload),
        });

        self.round = 3;
        Ok(())
    }

    /// Finalize: verify all R3 broadcasts, compute key share.
    fn finalize_keygen(&mut self) -> tecdsa_core::Result<()> {
        let n = self.all_parties.len();

        // Collect all_commitments for CombVf
        let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n)
            .map(|j| {
                let sender_index = (j + 1) as u16;
                let verified = self.r2_verified[j].as_ref().expect("verified data");
                (sender_index, verified.commitments.clone())
            })
            .collect();

        // Verify all other parties' R3 broadcasts + collect X points
        let mut x_points = Vec::with_capacity(n);
        for j in 0..n {
            let r3_bcast = self.r3_bcasts[j]
                .as_ref()
                .ok_or_else(|| TecdsaError::Other(format!("missing R3 bcast for party {j}")))?;

            if j == self.my_idx() {
                let r3_state = self.r3_state.as_ref().expect("own R3 state");
                x_points.push(r3_state.x_point);
            } else {
                let cl_pk_abc = &self.r2_verified[j]
                    .as_ref()
                    .expect("verified data")
                    .cl_pk_abc;
                let x_point = rounds::verify_r3(
                    &self.setup,
                    cl_pk_abc,
                    (j + 1) as u16,
                    &all_commitments,
                    r3_bcast,
                )
                .map_err(|e| {
                    TecdsaError::Other(format!("R3 verification failed for party {j}: {e}"))
                })?;
                x_points.push(x_point);
            }
        }

        // Compute final key share
        let r1_state = self
            .r1_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r1_state missing in finalize".into()))?;
        let r3_state = self
            .r3_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r3_state missing in finalize".into()))?;

        let all_cl_pk_abcs: Vec<(String, String, String)> = (0..n)
            .map(|j| {
                self.r2_verified[j]
                    .as_ref()
                    .expect("verified data")
                    .cl_pk_abc
                    .clone()
            })
            .collect();

        let key_share =
            rounds::keygen_finalize(r1_state, r3_state, &x_points, &self.setup, &all_cl_pk_abcs)
                .map_err(|e| TecdsaError::Other(format!("keygen_finalize failed: {e}")))?;

        self.output = Some(key_share);
        self.done = true;
        self.round = 4;
        Ok(())
    }
}

impl StateMachine for Wmy23KeygenMachine {
    type Output = Wmy23KeyShare;
    type Inbound = Wmy23KeygenMsg;
    type Outbound = Wmy23KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let from_idx = self
            .party_idx(from)
            .ok_or_else(|| TecdsaError::Other(format!("unknown party: {from}")))?;

        match msg {
            Wmy23KeygenMsg::Round1(data) => {
                if self.round != 1 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round1 in round {}",
                        self.round
                    )));
                }
                if self.r1_bcasts[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate R1 from party {from}"
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid R1 commitment length".into()));
                }
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&data);
                self.r1_bcasts[from_idx] = Some(KeygenR1Bcast { commitment });

                if self.all_r1_collected() {
                    self.transition_to_r2()?;
                }
            }
            Wmy23KeygenMsg::Round2(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2 in round {}",
                        self.round
                    )));
                }
                if self.r2_bcasts[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate R2 from party {from}"
                    )));
                }
                let r2_bcast = rounds::deserialize_r2(&data)
                    .map_err(|e| TecdsaError::Other(format!("R2 deserialize: {e}")))?;
                self.r2_bcasts[from_idx] = Some(r2_bcast);

                if self.all_r2_collected() {
                    self.transition_to_r3()?;
                }
            }
            Wmy23KeygenMsg::Round3(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round3 (P2P share) in round {}",
                        self.round
                    )));
                }
                if self.r2_shares[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate P2P share from party {from}"
                    )));
                }
                if data.len() != 64 {
                    return Err(TecdsaError::Other("invalid P2P share length".into()));
                }
                use elliptic_curve::PrimeField;
                let mut repr_v = k256::FieldBytes::default();
                repr_v.copy_from_slice(&data[..32]);
                let value = k256::Scalar::from_repr(repr_v)
                    .into_option()
                    .ok_or_else(|| TecdsaError::Other("invalid value scalar".into()))?;
                let mut repr_r = k256::FieldBytes::default();
                repr_r.copy_from_slice(&data[32..64]);
                let randomness = k256::Scalar::from_repr(repr_r)
                    .into_option()
                    .ok_or_else(|| TecdsaError::Other("invalid randomness scalar".into()))?;
                self.r2_shares[from_idx] = Some((value, randomness));

                if self.all_r2_collected() {
                    self.transition_to_r3()?;
                }
            }
            Wmy23KeygenMsg::Round4(data) => {
                if self.round != 3 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round4 in round {}",
                        self.round
                    )));
                }
                if self.r3_bcasts[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate R3 from party {from}"
                    )));
                }
                let r3_bcast = rounds::deserialize_r3(&data)
                    .map_err(|e| TecdsaError::Other(format!("R3 deserialize: {e}")))?;
                self.r3_bcasts[from_idx] = Some(r3_bcast);

                if self.all_r3_collected() {
                    self.finalize_keygen()?;
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
            .ok_or_else(|| TecdsaError::Other("keygen not complete".into()))
    }

    fn current_round(&self) -> u16 {
        self.round
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
