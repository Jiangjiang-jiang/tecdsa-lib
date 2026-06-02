// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for CGGMP20 threshold keygen.

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Group, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::dlog::DlogProof;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};
use tecdsa_vss::feldman;
use zeroize::Zeroize;

use crate::key_share::{Cggmp20CoreKeyShare, VssSetup};

use super::msg::{KeygenMsg, MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3};

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Cggmp20CoreKeyShare<C>),
    /// Sentinel so we can `std::mem::take` without leaving an invalid state.
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Round 1 state
// ---------------------------------------------------------------------------

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Configuration
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    // Own secrets generated at construction
    pub vss_shares: Vec<tecdsa_vss::shamir::Share<C>>,
    pub feldman_commitments: Vec<C::ProjectivePoint>,
    pub rid: [u8; 32],
    pub decommit_nonce: [u8; 32],
    pub schnorr_ephemeral: C::Scalar,
    pub schnorr_commitment: C::ProjectivePoint,

    // Outgoing messages queued at construction
    pub outgoing: Vec<Outgoing<KeygenMsg<C>>>,

    // Received messages
    pub round1_msgs: BTreeMap<PartyId, MsgRound1>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the initial Round1 state: generate secrets and queue Round1 broadcast.
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.local_party.id;
        let parties = config.parties.clone();
        let threshold = config.reconstruct_threshold(); // VSS reconstruction threshold
        let total = config.local_party.total;

        // 1. Generate random secret u_i
        let secret_u = C::random_scalar(rng);

        // 2. Feldman VSS split
        let (vss_shares, feldman_commitments) =
            feldman::split::<C>(&secret_u, threshold, total, rng);

        // 3. Sample rid
        let mut rid = [0u8; 32];
        rng.fill_bytes(&mut rid);

        // 4. Sample Schnorr ephemeral r_i, compute R_i = r_i * G
        let schnorr_ephemeral = C::random_scalar(rng);
        let schnorr_commitment = C::generator() * schnorr_ephemeral;

        // 5. Compute hash commitment over (rid || feldman_commitments || schnorr_commitment).
        //    The HashCommitment nonce serves as the decommit_nonce revealed in Round 2.
        let commit_msg = {
            let mut data = Vec::new();
            data.extend_from_slice(&rid);
            for com in &feldman_commitments {
                data.extend_from_slice(com.to_bytes().as_ref());
            }
            data.extend_from_slice(schnorr_commitment.to_bytes().as_ref());
            data
        };
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_msg, rng);

        // 6. Queue broadcast of MsgRound1
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: KeygenMsg::Round1(MsgRound1 {
                commitment: hash_commitment,
            }),
        }];

        Self {
            my_id,
            parties,
            threshold,
            total,
            vss_shares,
            feldman_commitments,
            rid,
            decommit_nonce,
            schnorr_ephemeral,
            schnorr_commitment,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    /// Number of messages we expect to receive (from all other parties).
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    /// Handle a Round1 message from another party.
    pub fn handle(&mut self, from: PartyId, msg: MsgRound1) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round1_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_msgs.insert(from, msg);
        Ok(())
    }

    /// Check if all expected Round1 messages have been received.
    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

    /// Transition to Round2: queue decommitment broadcast + VSS shares (p2p).
    pub fn advance(self) -> Round2State<C> {
        let mut outgoing: Vec<Outgoing<KeygenMsg<C>>> = Vec::new();

        // Broadcast decommitment data
        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: KeygenMsg::Round2Broad(MsgRound2Broad {
                rid: self.rid,
                feldman_commitments: self.feldman_commitments.clone(),
                schnorr_commitment: self.schnorr_commitment,
                decommit_nonce: self.decommit_nonce,
            }),
        });

        // Send VSS shares to each other party
        for &pid in &self.parties {
            if pid == self.my_id {
                continue;
            }
            // Find the share for party pid. VSS shares are 1-based: shares[j].index = j+1.
            // PartyId is 1-based. We need the share whose index == pid.0.
            let share = self
                .vss_shares
                .iter()
                .find(|s| s.index == pid.0)
                .expect("VSS share must exist for every party");
            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: KeygenMsg::Round2Uni(MsgRound2Uni {
                    vss_share: share.value,
                }),
            });
        }

        Round2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            own_vss_shares: self.vss_shares,
            feldman_commitments: self.feldman_commitments,
            rid: self.rid,
            schnorr_ephemeral: self.schnorr_ephemeral,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_broad: BTreeMap::new(),
            round2_uni: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2 state
// ---------------------------------------------------------------------------

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Config
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    // Own secrets
    pub own_vss_shares: Vec<tecdsa_vss::shamir::Share<C>>,
    pub feldman_commitments: Vec<C::ProjectivePoint>,
    pub rid: [u8; 32],
    pub schnorr_ephemeral: C::Scalar,

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, MsgRound1>,

    // Outgoing
    pub outgoing: Vec<Outgoing<KeygenMsg<C>>>,

    // Received
    pub round2_broad: BTreeMap<PartyId, MsgRound2Broad<C>>,
    pub round2_uni: BTreeMap<PartyId, MsgRound2Uni<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle_broad(
        &mut self,
        from: PartyId,
        msg: MsgRound2Broad<C>,
    ) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round2_broad.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_broad.insert(from, msg);
        Ok(())
    }

    pub fn handle_uni(&mut self, from: PartyId, msg: MsgRound2Uni<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round2_uni.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_uni.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_broad.len() == self.expected_count()
            && self.round2_uni.len() == self.expected_count()
    }

    /// Verify all hash commitments and Feldman share consistency.
    fn verify_round2_data(&self) -> tecdsa_core::Result<()> {
        // Verify each party's hash commitment against their decommitted data.
        for (&pid, broad) in &self.round2_broad {
            let round1 = self
                .round1_commitments
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round1 from {pid}")))?;

            let commit_msg = {
                let mut data = Vec::new();
                data.extend_from_slice(&broad.rid);
                for com in &broad.feldman_commitments {
                    data.extend_from_slice(com.to_bytes().as_ref());
                }
                data.extend_from_slice(broad.schnorr_commitment.to_bytes().as_ref());
                data
            };

            if !round1.commitment.verify(&commit_msg, &broad.decommit_nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} commitment verification failed"
                )));
            }
        }

        // Verify Feldman consistency for each received VSS share.
        let my_index = self.my_id.0;
        for (&pid, uni) in &self.round2_uni {
            let broad = self
                .round2_broad
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round2 broad from {pid}")))?;

            if !feldman::verify::<C>(&uni.vss_share, my_index, &broad.feldman_commitments) {
                return Err(TecdsaError::InvalidShare(format!(
                    "party {pid} Feldman share verification failed"
                )));
            }
        }

        Ok(())
    }

    /// Compute public verification shares `X_j` for each party j.
    fn compute_public_shares(&self) -> Vec<C::ProjectivePoint> {
        let mut public_shares = Vec::with_capacity(self.total as usize);
        for j in 1..=self.total {
            let x = C::Scalar::from(u64::from(j));
            let mut point = C::ProjectivePoint::identity();

            // Own polynomial evaluation at j
            let mut x_pow = C::Scalar::ONE;
            for com in &self.feldman_commitments {
                point += *com * x_pow;
                x_pow *= x;
            }

            // Add all other parties' polynomial evaluations at j
            for broad in self.round2_broad.values() {
                let mut x_pow = C::Scalar::ONE;
                for com in &broad.feldman_commitments {
                    point += *com * x_pow;
                    x_pow *= x;
                }
            }

            public_shares.push(point);
        }
        public_shares
    }

    /// Transition to Round3: verify commitments + Feldman consistency, compute
    /// secret share, generate Schnorr proof.
    pub fn advance(mut self) -> tecdsa_core::Result<Round3State<C>> {
        self.verify_round2_data()?;

        let my_index = self.my_id.0;

        // Compute combined rid = XOR(all rids).
        let mut combined_rid = self.rid;
        for broad in self.round2_broad.values() {
            for (i, b) in broad.rid.iter().enumerate() {
                combined_rid[i] ^= b;
            }
        }

        // Compute secret share x_i = sum of all received vss_shares + own_share.
        let own_share_value = self
            .own_vss_shares
            .iter()
            .find(|s| s.index == my_index)
            .expect("own VSS share must exist")
            .value;
        let mut x_i = own_share_value;
        for uni in self.round2_uni.values() {
            x_i += uni.vss_share;
        }

        // Compute public key Q = sum of all feldman_commitments[0] (constant terms).
        let mut public_key = self.feldman_commitments[0];
        for broad in self.round2_broad.values() {
            public_key += broad.feldman_commitments[0];
        }

        let public_shares = self.compute_public_shares();

        // Generate Schnorr proof of x_i with combined rid as aux data.
        let own_public_share = public_shares[(my_index - 1) as usize];
        let schnorr_proof = DlogProof::<C>::prove(
            &x_i,
            &self.schnorr_ephemeral,
            &own_public_share,
            &combined_rid,
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: KeygenMsg::Round3(MsgRound3 { schnorr_proof }),
        }];

        // Zeroize secrets not carried to the next round
        self.schnorr_ephemeral.zeroize();
        for share in &mut self.own_vss_shares {
            share.value.zeroize();
        }

        Ok(Round3State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            secret_share: x_i,
            public_key,
            public_shares,
            combined_rid,
            outgoing,
            round3_msgs: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 3 state
// ---------------------------------------------------------------------------

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Config
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    // Computed values
    pub secret_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
    pub combined_rid: [u8; 32],

    // Outgoing
    pub outgoing: Vec<Outgoing<KeygenMsg<C>>>,

    // Received
    pub round3_msgs: BTreeMap<PartyId, MsgRound3<C>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound3<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round3_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round3_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round3_msgs.len() == self.expected_count()
    }

    /// Verify all Schnorr proofs and produce the final `Cggmp20CoreKeyShare`.
    pub fn finish(self) -> tecdsa_core::Result<Cggmp20CoreKeyShare<C>> {
        // Verify every other party's Schnorr proof.
        for (&pid, msg) in &self.round3_msgs {
            let party_public_share = self.public_shares[(pid.0 - 1) as usize];
            if !msg
                .schnorr_proof
                .verify(&party_public_share, &self.combined_rid)
            {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} Schnorr proof verification failed"
                )));
            }
        }

        // Party index is 0-based in Cggmp20CoreKeyShare.
        let party_index = self.my_id.0 - 1;

        Ok(Cggmp20CoreKeyShare {
            party_index,
            secret_share: self.secret_share,
            public_key: self.public_key,
            public_shares: self.public_shares,
            vss_setup: VssSetup {
                threshold: self.threshold,
                total: self.total,
            },
        })
    }
}
