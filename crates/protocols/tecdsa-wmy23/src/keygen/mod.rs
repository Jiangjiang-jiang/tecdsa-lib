// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 threshold key generation protocol.
//!
//! A commit/reveal Feldman-VSS distributed key generation producing
//! `(t+1, n)` Shamir shares of the joint ECDSA key, plus per-party CL-HSM
//! key material for MtAwc.
//!
//! ## Protocol Rounds
//!
//! 1. **Commitment:** each party broadcasts a hash commitment to its Feldman
//!    commitments and CL public key.
//! 2. **Decommit + share distribution:** broadcast decommitment (Feldman
//!    commitments + CL public key) and send each party its private VSS share.
//! 3. **Finalize:** verify all commitments and VSS shares, then combine into a
//!    threshold key share.
//!
//! ## Implementation
//!
//! The round logic lives in the `rounds` module as pure functions. The
//! `StateMachine` impl wraps them, broadcasting the decommitment and routing
//! the per-recipient VSS shares as point-to-point messages.
//!
//! With bicycl-rs v0.2.2, all CL types including `ClSetup` are `Send`,
//! so both `Wmy23KeyShare` and the keygen machine satisfy the
//! `StateMachine: Send + 'static` bound.
//!
//! Reference: Wang, Mei, Yu. "Real Threshold ECDSA." NDSS 2023, Section 3.2.

pub mod msg;
pub mod rounds;

use elliptic_curve::PrimeField;
use msg::Wmy23KeygenMsg;
use rounds::{KeygenR1Bcast, KeygenR1State, KeygenR2Bcast};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use crate::key_share::Wmy23KeyShare;

/// WMY23 key generation state machine.
///
/// Drives a single party through the Feldman-VSS keygen protocol using the
/// pure functions in the `rounds` module.
///
/// ## Round flow
///
/// - **Round 0 (init):** on construction, runs `keygen_round1` and queues
///   the Round 1 commitment broadcast.
/// - **Round 1 (collect commitments):** receives commitments from all other
///   parties.  Once all are received, broadcasts the Round 2 decommitment and
///   sends each party its private VSS share.
/// - **Round 2 (collect decommitments + shares):** receives decommitments and
///   private VSS shares from all other parties.  Once both are complete, runs
///   `keygen_finalize`.
///
/// Since bicycl-rs v0.2.2, `ClSetup` is `Send`, so it is stored directly
/// in the machine and reused across round transitions.
pub struct Wmy23KeygenMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    _threshold: u16,
    /// CL setup stored directly (Send since bicycl-rs v0.2.2).
    setup: tecdsa_class_group::cl::ClSetup,
    /// Round 1 state (from keygen_round1).
    r1_state: Option<KeygenR1State>,
    /// Collected Round 1 broadcasts from all parties (indexed by party order).
    r1_bcasts: Vec<Option<KeygenR1Bcast>>,
    /// Collected Round 2 broadcasts from all parties (indexed by party order).
    r2_bcasts: Vec<Option<KeygenR2Bcast>>,
    /// Collected private VSS shares from all parties (indexed by sender order).
    /// `r2_shares[j]` is the share party `j` sent to this party.
    r2_shares: Vec<Option<k256::Scalar>>,
    /// Outgoing messages to drain.
    outgoing: Vec<Outgoing<Wmy23KeygenMsg>>,
    /// Current round (1 = collecting R1, 2 = collecting R2, 3 = done).
    round: u16,
    /// Final output (set when done).
    output: Option<Wmy23KeyShare>,
    done: bool,
}

impl Wmy23KeygenMachine {
    /// Create a new WMY23 keygen state machine.
    ///
    /// Immediately runs keygen Round 1 (key generation + VSS dealing +
    /// commitment) and queues the Round 1 broadcast for all other parties.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All party identifiers in consistent order.
    /// * `threshold` - Reconstruction threshold `t+1` (number of signers
    ///   required; the secret is shared with a degree-`t` polynomial).
    /// * `cl_setup_seed` - Seed for CL setup creation.
    /// * `use_128bit_security` - If true, use 128-bit security CL parameters
    ///   (1828-bit discriminant).  If false, use insecure p=7 parameters
    ///   (for fast testing only).
    ///
    /// # Errors
    ///
    /// Returns an error if CL key generation fails or the threshold is invalid.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        cl_setup_seed: &str,
        use_128bit_security: bool,
    ) -> tecdsa_core::Result<Self> {
        let n = all_parties.len();
        let my_idx = all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not found in all_parties".into()))?;

        // Create a ClSetup and store it for use across all rounds.
        let mut setup = if use_128bit_security {
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(cl_setup_seed)
        } else {
            tecdsa_class_group::cl::ClSetup::new_secp256k1(cl_setup_seed)
        }
        .map_err(|e| TecdsaError::Other(format!("ClSetup creation failed: {e}")))?;

        let mut rng = rand::thread_rng();
        let (r1_state, r1_bcast) = rounds::keygen_round1(
            &mut setup,
            cl_setup_seed,
            my_idx,
            n as u16,
            threshold,
            use_128bit_security,
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("keygen_round1 failed: {e}")))?;

        // Store our own R1 broadcast
        let mut r1_bcasts: Vec<Option<KeygenR1Bcast>> = vec![None; n];
        r1_bcasts[my_idx] = Some(r1_bcast.clone());

        // Queue Round 1 broadcast to all other parties
        let mut outgoing = Vec::new();
        let commitment_bytes = r1_bcast.commitment.to_vec();
        for party in &all_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: tecdsa_protocol::Recipient::Party(*party),
                    msg: Wmy23KeygenMsg::Round1(commitment_bytes.clone()),
                });
            }
        }

        Ok(Self {
            my_id,
            all_parties,
            _threshold: threshold,
            setup,
            r1_state: Some(r1_state),
            r1_bcasts,
            r2_bcasts: vec![None; n],
            r2_shares: vec![None; n],
            outgoing,
            round: 1,
            output: None,
            done: false,
        })
    }

    /// Returns this party's index in the all_parties list.
    fn my_idx(&self) -> usize {
        self.all_parties
            .iter()
            .position(|p| *p == self.my_id)
            .expect("my_id must be in all_parties")
    }

    /// Returns the index of a given party.
    fn party_idx(&self, party: PartyId) -> Option<usize> {
        self.all_parties.iter().position(|p| *p == party)
    }

    /// Check if all R1 broadcasts have been collected.
    fn all_r1_collected(&self) -> bool {
        self.r1_bcasts.iter().all(|b| b.is_some())
    }

    /// Check if all R2 broadcasts AND private VSS shares have been collected.
    fn all_r2_collected(&self) -> bool {
        self.r2_bcasts.iter().all(|b| b.is_some()) && self.r2_shares.iter().all(|s| s.is_some())
    }

    /// Serialize a KeygenR2Bcast into bytes.
    ///
    /// Format: nonce (32) || num_commitments (4 LE) ||
    ///   for each commitment: len (4 LE) || bytes ||
    ///   for each abc string: len (4 LE) || bytes
    fn serialize_r2(r2: &KeygenR2Bcast) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&r2.nonce);
        data.extend_from_slice(&(r2.feldman_commitments.len() as u32).to_le_bytes());
        for c in &r2.feldman_commitments {
            data.extend_from_slice(&(c.len() as u32).to_le_bytes());
            data.extend_from_slice(c);
        }
        for s in [&r2.cl_pk_abc.0, &r2.cl_pk_abc.1, &r2.cl_pk_abc.2] {
            let bytes = s.as_bytes();
            data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(bytes);
        }
        data
    }

    /// Deserialize a KeygenR2Bcast from bytes.
    fn deserialize_r2(data: &[u8]) -> Result<KeygenR2Bcast, String> {
        let mut pos = 0usize;
        let read_u32 = |data: &[u8], pos: &mut usize| -> Result<usize, String> {
            if *pos + 4 > data.len() {
                return Err("R2 truncated reading length".into());
            }
            let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            Ok(v)
        };

        if data.len() < 32 {
            return Err("R2 data too short".into());
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let num_coms = read_u32(data, &mut pos)?;
        let mut feldman_commitments = Vec::with_capacity(num_coms);
        for _ in 0..num_coms {
            let len = read_u32(data, &mut pos)?;
            if pos + len > data.len() {
                return Err("R2 truncated at commitment bytes".into());
            }
            feldman_commitments.push(data[pos..pos + len].to_vec());
            pos += len;
        }

        let mut strings = Vec::with_capacity(3);
        for _ in 0..3 {
            let len = read_u32(data, &mut pos)?;
            if pos + len > data.len() {
                return Err("R2 truncated at string data".into());
            }
            let s = std::str::from_utf8(&data[pos..pos + len])
                .map_err(|e| format!("invalid UTF-8: {e}"))?
                .to_string();
            pos += len;
            strings.push(s);
        }

        Ok(KeygenR2Bcast {
            nonce,
            feldman_commitments,
            cl_pk_abc: (strings.remove(0), strings.remove(0), strings.remove(0)),
        })
    }

    /// Transition from R1 to R2: broadcast decommitment + send VSS shares P2P.
    fn transition_to_r2(&mut self) -> tecdsa_core::Result<()> {
        let r1_state = self
            .r1_state
            .as_ref()
            .ok_or_else(|| TecdsaError::Other("r1_state missing".into()))?;

        let r2_bcast = rounds::keygen_round2_bcast(r1_state);
        let my_idx = self.my_idx();

        // Store our own R2 broadcast and our own VSS share to ourselves.
        self.r2_bcasts[my_idx] = Some(r2_bcast.clone());
        self.r2_shares[my_idx] = Some(rounds::keygen_round2_share(r1_state, my_idx));

        // Queue R2 broadcast + per-recipient private VSS share.
        let payload = Self::serialize_r2(&r2_bcast);
        for party in self.all_parties.clone() {
            if party == self.my_id {
                continue;
            }
            let recipient_idx = self
                .party_idx(party)
                .ok_or_else(|| TecdsaError::Other("recipient not in all_parties".into()))?;
            let share = rounds::keygen_round2_share(r1_state, recipient_idx);

            self.outgoing.push(Outgoing {
                to: tecdsa_protocol::Recipient::Party(party),
                msg: Wmy23KeygenMsg::Round2(payload.clone()),
            });
            self.outgoing.push(Outgoing {
                to: tecdsa_protocol::Recipient::Party(party),
                msg: Wmy23KeygenMsg::Round3(share.to_repr().to_vec()),
            });
        }

        self.round = 2;
        Ok(())
    }

    /// Finalize: verify commitments + VSS shares and compute the key share.
    fn finalize_keygen(&mut self) -> tecdsa_core::Result<()> {
        let r1_state = self
            .r1_state
            .take()
            .ok_or_else(|| TecdsaError::Other("r1_state missing in finalize".into()))?;

        let r1_bcasts: Vec<KeygenR1Bcast> = self
            .r1_bcasts
            .iter()
            .map(|b| b.clone().expect("all R1 bcasts should be present"))
            .collect();
        let r2_bcasts: Vec<KeygenR2Bcast> = self
            .r2_bcasts
            .iter()
            .map(|b| b.clone().expect("all R2 bcasts should be present"))
            .collect();
        let received_shares: Vec<k256::Scalar> = self
            .r2_shares
            .iter()
            .map(|s| s.expect("all VSS shares should be present"))
            .collect();

        let key_share = rounds::keygen_finalize(
            r1_state,
            &r1_bcasts,
            &r2_bcasts,
            &received_shares,
            &self.setup,
        )
        .map_err(|e| TecdsaError::Other(format!("keygen_finalize failed: {e}")))?;

        self.output = Some(key_share);
        self.done = true;
        self.round = 3;
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
                        "unexpected Round1 message in round {}",
                        self.round
                    )));
                }
                if self.r1_bcasts[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid R1 commitment length".into()));
                }
                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&data);
                self.r1_bcasts[from_idx] = Some(KeygenR1Bcast { commitment });

                // Check if we can transition to Round 2
                if self.all_r1_collected() {
                    self.transition_to_r2()?;
                }
            }
            Wmy23KeygenMsg::Round2(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round2 message in round {}",
                        self.round
                    )));
                }
                if self.r2_bcasts[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate Round2 broadcast from party {from}"
                    )));
                }
                let r2_bcast = Self::deserialize_r2(&data)
                    .map_err(|e| TecdsaError::Other(format!("R2 deserialize: {e}")))?;

                self.r2_bcasts[from_idx] = Some(r2_bcast);

                if self.all_r2_collected() {
                    self.finalize_keygen()?;
                }
            }
            Wmy23KeygenMsg::Round3(data) => {
                if self.round != 2 {
                    return Err(TecdsaError::Other(format!(
                        "unexpected Round3 (VSS share) message in round {}",
                        self.round
                    )));
                }
                if self.r2_shares[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate VSS share from party {from}"
                    )));
                }
                if data.len() != 32 {
                    return Err(TecdsaError::Other("invalid VSS share length".into()));
                }
                let mut repr = k256::FieldBytes::default();
                repr.copy_from_slice(&data);
                let share = k256::Scalar::from_repr(repr)
                    .into_option()
                    .ok_or_else(|| TecdsaError::Other("invalid scalar in VSS share".into()))?;
                self.r2_shares[from_idx] = Some(share);

                if self.all_r2_collected() {
                    self.finalize_keygen()?;
                }
            }
            _ => {
                return Err(TecdsaError::Other("unexpected message type".into()));
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
