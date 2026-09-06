// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for GGN16 threshold keygen.
//!
//! The protocol proceeds in 2 rounds:
//! 1. **Commitment:** each party broadcasts a hash commitment to its public
//!    key contribution y_i = x_i * G.
//! 2. **Decommit + Encrypt + Prove:** each party broadcasts the decommitment,
//!    its Paillier-encrypted secret share alpha_i = E(x_i), and a PdlSlack
//!    proof that alpha_i encrypts the discrete log of y_i.
//!
//! After Round 2, each party computes:
//! - alpha = sum(alpha_i) = E(sum(x_i)) = E(x) via homomorphic addition
//! - y = sum(y_i) = (sum(x_i)) * G = x * G as the joint public key

#![allow(non_snake_case)]

use std::{collections::BTreeMap, marker::PhantomData};

use elliptic_curve::{
    group::{Group, GroupEncoding},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    threshold::{DecryptionShare, ThresholdSetup},
    zk::pdl_slack::{PdlSlackProof, PdlSlackStatement, PdlSlackWitness},
    BigIntExt,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};

use super::msg::{Ggn16KeygenMsg, KeygenRound1Msg, KeygenRound2Msg};
use crate::key_share::Ggn16KeyShare;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a GGN16 keygen participant.
///
/// Requires pre-existing threshold Paillier setup (from a trusted dealer)
/// and Ring-Pedersen auxiliary parameters for ZK proofs.
pub(crate) struct KeygenConfig {
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
}

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
    Done(Ggn16KeyShare<C>),
    /// Sentinel so we can `std::mem::take` without leaving an invalid state.
    #[default]
    Poisoned,
}

// ---------------------------------------------------------------------------
// Round 1 state -- Commitment
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

    // Threshold Paillier setup (shared across all parties)
    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,

    // Ring-Pedersen auxiliary parameters
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,

    // Own secrets generated at construction
    pub x_i: C::Scalar,
    pub y_i: C::ProjectivePoint,
    pub y_i_bytes: Vec<u8>,
    pub decommit_nonce: [u8; 32],
    pub alpha_i: Integer,
    pub alpha_i_nonce: Integer,

    // Outgoing messages queued at construction
    pub outgoing: Vec<Outgoing<Ggn16KeygenMsg<C>>>,

    // Received round 1 messages
    pub round1_msgs: BTreeMap<PartyId, KeygenRound1Msg>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the initial Round1 state: generate secrets and queue the
    /// Round 1 commitment broadcast.
    pub fn new(config: KeygenConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.my_id;
        let parties = config.all_parties;
        let threshold = config.threshold;
        let total = config.total;

        // 1. Sample x_i, compute y_i = x_i * G
        let x_i = C::random_scalar(rng);
        let y_i = C::generator() * x_i;

        // 2. Serialize y_i for commitment and later broadcast
        let y_i_bytes: Vec<u8> = y_i.to_bytes().as_ref().to_vec();

        // 3. Hash commitment: H(nonce || y_i_bytes)
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&y_i_bytes, rng);

        // 4. Encrypt x_i under the shared Paillier key
        let x_i_repr = x_i.to_repr();
        let x_i_integer = Integer::from_bytes_msf(x_i_repr.as_ref());
        let (alpha_i, alpha_i_nonce) = config
            .threshold_setup
            .ek
            .encrypt_with_random(rng, &x_i_integer)
            .expect("Paillier encryption must succeed for valid plaintext");

        // 5. Queue broadcast of Round 1 commitment
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16KeygenMsg::Round1(KeygenRound1Msg {
                commitment: hash_commitment,
            }),
        }];

        Self {
            my_id,
            parties,
            threshold,
            total,
            threshold_setup: config.threshold_setup,
            decryption_share: config.decryption_share,
            h1: config.h1,
            h2: config.h2,
            N_tilde: config.N_tilde,
            x_i,
            y_i,
            y_i_bytes,
            decommit_nonce,
            alpha_i,
            alpha_i_nonce,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: KeygenRound1Msg) -> tecdsa_core::Result<()> {
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

    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

    /// Transition to Round 2: generate the PdlSlack proof and queue the
    /// decommitment + encrypted share + proof broadcast.
    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> Round2State<C> {
        // Build the PdlSlack statement and witness
        let ek = &self.threshold_setup.ek;
        let statement = PdlSlackStatement::<C> {
            ciphertext: self.alpha_i.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q: self.y_i,
            G: C::generator(),
            h1: self.h1.clone(),
            h2: self.h2.clone(),
            N_tilde: self.N_tilde.clone(),
        };

        let x_i_repr = self.x_i.to_repr();
        let x_i_integer = Integer::from_bytes_msf(x_i_repr.as_ref());
        let witness = PdlSlackWitness {
            x: x_i_integer,
            r: self.alpha_i_nonce.clone(),
        };

        let proof = PdlSlackProof::prove(&witness, &statement, rng);
        let proof_bytes = proof.to_bytes();

        // Queue the Round 2 broadcast
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16KeygenMsg::Round2(KeygenRound2Msg {
                y_i_bytes: self.y_i_bytes.clone(),
                nonce: self.decommit_nonce,
                alpha_i: self.alpha_i.clone(),
                alpha_i_nonce: self.alpha_i_nonce.clone(),
                proof: proof_bytes,
                _marker: PhantomData,
            }),
        }];

        // Zeroize encryption randomness not carried to the next round
        self.alpha_i_nonce = Integer::from(0u32);

        Round2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            threshold_setup: self.threshold_setup,
            decryption_share: self.decryption_share,
            h1: self.h1,
            h2: self.h2,
            N_tilde: self.N_tilde,
            x_i: self.x_i,
            y_i: self.y_i,
            alpha_i: self.alpha_i,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2 state -- Decommit + Encrypt + Prove
// ---------------------------------------------------------------------------

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Configuration
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    // Threshold Paillier setup
    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,

    // Ring-Pedersen auxiliary parameters
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,

    // Own secrets
    pub x_i: C::Scalar,
    pub y_i: C::ProjectivePoint,
    pub alpha_i: Integer,

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, KeygenRound1Msg>,

    // Outgoing
    pub outgoing: Vec<Outgoing<Ggn16KeygenMsg<C>>>,

    // Received round 2 messages
    pub round2_msgs: BTreeMap<PartyId, KeygenRound2Msg<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: KeygenRound2Msg<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round2_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_msgs.len() == self.expected_count()
    }

    /// Verify all round 2 data and produce the final `Ggn16KeyShare`.
    ///
    /// For each other party:
    /// 1. Verify the hash commitment from Round 1 matches the decommitted y_i.
    /// 2. Deserialize y_i from bytes and verify it is a valid curve point.
    /// 3. Verify the PdlSlack proof that alpha_i encrypts the discrete log of y_i.
    ///
    /// Then compute:
    /// - alpha = sum(alpha_i) via homomorphic addition
    /// - y = sum(y_i) as the joint public key
    pub fn finish(self) -> tecdsa_core::Result<Ggn16KeyShare<C>> {
        let ek = &self.threshold_setup.ek;

        // Collect all public shares: own y_i first, then by party order
        let mut public_shares: Vec<C::ProjectivePoint> = Vec::with_capacity(self.total as usize);
        let mut all_alpha: Vec<Integer> = Vec::with_capacity(self.total as usize);

        // Process in party order (1..=total)
        for pid_val in 1..=self.total {
            let pid = PartyId(pid_val);
            if pid == self.my_id {
                public_shares.push(self.y_i);
                all_alpha.push(self.alpha_i.clone());
            } else {
                let r2 = self.round2_msgs.get(&pid).ok_or_else(|| {
                    TecdsaError::Other(format!("missing round2 message from party {pid}"))
                })?;

                // 1. Verify hash commitment
                let r1 = self.round1_commitments.get(&pid).ok_or_else(|| {
                    TecdsaError::Other(format!("missing round1 commitment from party {pid}"))
                })?;
                if !r1.commitment.verify(&r2.y_i_bytes, &r2.nonce) {
                    return Err(TecdsaError::InvalidCommitment(format!(
                        "party {pid} commitment verification failed"
                    )));
                }

                // 2. Deserialize y_j from bytes
                let y_j = deserialize_point::<C>(&r2.y_i_bytes).map_err(|_| {
                    TecdsaError::Other(format!("party {pid} sent invalid y_i point encoding"))
                })?;

                // 3. Verify y_j is not identity
                if y_j == C::ProjectivePoint::identity() {
                    return Err(TecdsaError::InvalidShare(format!(
                        "party {pid} sent identity point as public share"
                    )));
                }

                // 4. Verify PdlSlack proof
                let proof = PdlSlackProof::<C>::from_bytes(&r2.proof).ok_or_else(|| {
                    TecdsaError::InvalidProof(format!(
                        "party {pid} PdlSlack proof deserialization failed"
                    ))
                })?;

                let statement = PdlSlackStatement::<C> {
                    ciphertext: r2.alpha_i.clone(),
                    ek_n: ek.n().clone(),
                    ek_nn: ek.nn().clone(),
                    Q: y_j,
                    G: C::generator(),
                    h1: self.h1.clone(),
                    h2: self.h2.clone(),
                    N_tilde: self.N_tilde.clone(),
                };

                proof.verify(&statement).map_err(|_| {
                    TecdsaError::InvalidProof(format!(
                        "party {pid} PdlSlack proof verification failed"
                    ))
                })?;

                public_shares.push(y_j);
                all_alpha.push(r2.alpha_i.clone());
            }
        }

        // Compute joint public key: y = sum(y_i)
        let mut public_key = C::ProjectivePoint::identity();
        for y_j in &public_shares {
            public_key += *y_j;
        }

        // Compute global ciphertext: alpha = E(x) = sum(alpha_i) via
        // homomorphic addition under the shared Paillier key.
        let mut alpha = all_alpha[0].clone();
        for a_j in &all_alpha[1..] {
            alpha = ek
                .oadd(&alpha, a_j)
                .map_err(|e| TecdsaError::Other(format!("homomorphic addition failed: {e}")))?;
        }

        Ok(Ggn16KeyShare {
            party_index: self.my_id.0,
            secret_share: self.x_i,
            public_key,
            public_shares,
            alpha,
            threshold_setup: self.threshold_setup,
            decryption_share: self.decryption_share,
            h1: self.h1,
            h2: self.h2,
            N_tilde: self.N_tilde,
            threshold: self.threshold,
            total: self.total,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deserialize a projective point from its compressed SEC1 byte encoding.
fn deserialize_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, ()>
where
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let buf_len = repr.as_ref().len();
    if bytes.len() != buf_len {
        return Err(());
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    let opt = C::ProjectivePoint::from_bytes(&repr);
    Option::from(opt).ok_or(())
}
