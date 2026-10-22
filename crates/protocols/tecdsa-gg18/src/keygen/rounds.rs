// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for GG18 threshold keygen.
//!
//! The protocol proceeds in 4 rounds:
//! 1. Commitment: each party broadcasts a hash commitment to its public data.
//! 2. Decommit + VSS: each party broadcasts the opening and sends Feldman
//!    VSS shares via P2P.
//! 3. `DLog` proof: each party broadcasts a Schnorr proof for its public share.
//! 4. Verify: each party verifies all proofs. No messages are sent.

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Group, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    zk::{mta_range::NTildeParams, pi_mod},
    BigIntExt,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};
use tecdsa_vss::feldman;
use zeroize::Zeroize;

use super::msg::{
    Gg18KeygenMsg, MsgRound1, MsgRound2Broad, MsgRound2Uni, MsgRound3, SerInteger, PI_MOD_SECURITY,
};
use crate::key_share::{Gg18KeyShare, VssSetup};

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
    Done(Gg18KeyShare<C>),
    /// Sentinel so we can `std::mem::take` without leaving an invalid state.
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Round 1 state — Commitment
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
    pub y_i: C::ProjectivePoint,
    pub decommit_nonce: [u8; 32],
    pub schnorr_ephemeral: C::Scalar,

    // Paillier key pair
    pub dk: tecdsa_paillier::DecryptionKey,
    pub ek: tecdsa_paillier::EncryptionKey,

    // Ring-Pedersen N_tilde parameters
    pub n_tilde_params: NTildeParams,

    // Outgoing messages queued at construction
    pub outgoing: Vec<Outgoing<Gg18KeygenMsg<C>>>,

    // Received messages
    pub round1_msgs: BTreeMap<PartyId, MsgRound1>,
}

/// Pre-generated Paillier keys and Ring-Pedersen parameters for a party.
///
/// This allows callers to inject pre-generated keys (e.g., with smaller
/// primes for testing) rather than performing expensive key generation
/// inside the state machine constructor.
pub struct PaillierPrecomputed {
    /// Paillier decryption key (contains p, q).
    pub dk: tecdsa_paillier::DecryptionKey,
    /// Ring-Pedersen parameters `(N', h_1, h_2)`.
    pub n_tilde_params: NTildeParams,
}

/// Generate Ring-Pedersen `NTildeParams` from a Paillier decryption key.
///
/// Uses a fresh RSA modulus `N' = p' * q'` from `dk_tilde`, with generators
/// `h1` random in `Z*_{N'}` and `h2 = h1^{-xhi} mod N'`.
///
/// # Panics
///
/// Panics if modular exponentiation or inversion fails, which should not
/// happen for valid Paillier primes.
pub fn generate_n_tilde(
    dk_tilde: &tecdsa_paillier::DecryptionKey,
    rng: &mut impl CryptoRngCore,
) -> NTildeParams {
    let n_tilde = dk_tilde.n().clone();
    let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
    // xhi is a random value in [0, 2^256)
    let xhi_bound = Integer::two_pow(256);
    let xhi = xhi_bound.sample_below_ref(rng);
    // h2 = h1^(-xhi) mod N'
    let h1_xhi = Integer::from(
        h1.pow_mod_ref(&xhi, &n_tilde)
            .expect("pow_mod must succeed"),
    );
    let h2 = h1_xhi
        .invert(&n_tilde)
        .expect("h1^xhi must be invertible mod N_tilde");

    NTildeParams {
        N_tilde: n_tilde,
        h1,
        h2,
    }
}

impl PaillierPrecomputed {
    /// Generate fresh per-party long-term key material: a Paillier keypair plus
    /// Ring-Pedersen parameters (derived from a second Paillier modulus). Factored
    /// out so benchmarks can time this (n,t)-independent setup separately from the
    /// interactive DKG (which should consume it via `new_with_precomputed`).
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let dk =
            tecdsa_paillier::DecryptionKey::generate(rng).expect("Paillier keygen must succeed");
        let dk_tilde = tecdsa_paillier::DecryptionKey::generate(rng)
            .expect("Paillier keygen for N_tilde must succeed");
        let n_tilde_params = generate_n_tilde(&dk_tilde, rng);
        PaillierPrecomputed { dk, n_tilde_params }
    }
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the initial Round1 state: generate secrets and queue Round1 broadcast.
    ///
    /// This is the production constructor that generates full-size Paillier keys.
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let precomputed = PaillierPrecomputed::generate(rng);
        Self::new_with_precomputed(config, precomputed, rng)
    }

    /// Create the initial Round1 state with pre-generated Paillier keys.
    ///
    /// This constructor is useful for testing with smaller primes, where
    /// Paillier key generation is done outside the state machine.
    pub fn new_with_precomputed(
        config: &SessionConfig,
        precomputed: PaillierPrecomputed,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let my_id = config.local_party.id;
        let parties = config.parties.clone();
        let threshold = config.reconstruct_threshold(); // VSS reconstruction threshold
        let total = config.local_party.total;

        // 1. Sample u_i, compute y_i = u_i * G
        let secret_u = C::random_scalar(rng);
        let y_i = C::generator() * secret_u;

        // 2. Feldman VSS split of u_i
        let (vss_shares, feldman_commitments) =
            feldman::split::<C>(&secret_u, threshold, total, rng);

        let dk = precomputed.dk;
        let ek = dk.encryption_key().clone();
        let n_tilde_params = precomputed.n_tilde_params;

        // 3. Schnorr ephemeral for DLog proof (used in Round 3)
        let schnorr_ephemeral = C::random_scalar(rng);

        // 4. Hash commitment: H(y_i || ek_N || N' || h1 || h2 || feldman_commitments)
        let commit_msg = build_commit_data::<C>(&y_i, &ek, &n_tilde_params, &feldman_commitments);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_msg, rng);

        // 5. Queue broadcast of MsgRound1
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18KeygenMsg::Round1(MsgRound1 {
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
            y_i,
            decommit_nonce,
            schnorr_ephemeral,
            dk,
            ek,
            n_tilde_params,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

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

    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

    /// Transition to Round2: queue decommitment broadcast + VSS shares (p2p).
    pub fn advance(self) -> Round2State<C> {
        let mut outgoing: Vec<Outgoing<Gg18KeygenMsg<C>>> = Vec::new();

        // Broadcast decommitment data
        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18KeygenMsg::Round2Broad(MsgRound2Broad {
                y_i: self.y_i,
                ek: self.ek.clone(),
                n_tilde: SerInteger(self.n_tilde_params.N_tilde.clone()),
                h1: SerInteger(self.n_tilde_params.h1.clone()),
                h2: SerInteger(self.n_tilde_params.h2.clone()),
                feldman_commitments: self.feldman_commitments.clone(),
                decommit_nonce: self.decommit_nonce,
            }),
        });

        // Send VSS shares to each other party
        for &pid in &self.parties {
            if pid == self.my_id {
                continue;
            }
            let share = self
                .vss_shares
                .iter()
                .find(|s| s.index == pid.0)
                .expect("VSS share must exist for every party");
            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Gg18KeygenMsg::Round2Uni(MsgRound2Uni {
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
            y_i: self.y_i,
            ek: self.ek,
            dk: self.dk,
            n_tilde_params: self.n_tilde_params,
            schnorr_ephemeral: self.schnorr_ephemeral,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_broad: BTreeMap::new(),
            round2_uni: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2 state — Decommit + VSS
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
    pub y_i: C::ProjectivePoint,
    pub ek: tecdsa_paillier::EncryptionKey,
    pub dk: tecdsa_paillier::DecryptionKey,
    pub n_tilde_params: NTildeParams,
    pub schnorr_ephemeral: C::Scalar,

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, MsgRound1>,

    // Outgoing
    pub outgoing: Vec<Outgoing<Gg18KeygenMsg<C>>>,

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

    /// Verify hash commitments and Feldman share consistency.
    fn verify_round2_data(&self) -> tecdsa_core::Result<()> {
        for (&pid, broad) in &self.round2_broad {
            let round1 = self
                .round1_commitments
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round1 from {pid}")))?;

            // Reconstruct the NTildeParams from the deserialized fields
            let ntilde = NTildeParams {
                N_tilde: broad.n_tilde.0.clone(),
                h1: broad.h1.0.clone(),
                h2: broad.h2.0.clone(),
            };

            let commit_msg =
                build_commit_data::<C>(&broad.y_i, &broad.ek, &ntilde, &broad.feldman_commitments);

            if !round1.commitment.verify(&commit_msg, &broad.decommit_nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} commitment verification failed"
                )));
            }
        }

        // Verify Feldman consistency for each received VSS share
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
    ///
    /// `X_j = sum over all parties' Feldman commitments evaluated at j`.
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

    /// Transition to Round3: verify commitments + Feldman, compute secret share,
    /// generate Schnorr `DLog` proof and Pi_mod proof.
    pub fn advance(mut self) -> tecdsa_core::Result<Round3State<C>> {
        self.verify_round2_data()?;

        let my_index = self.my_id.0;

        // Compute secret share x_i = own_share(my_index) + sum of received shares
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

        // Compute joint public key Y = sum of all y_i (constant terms of Feldman polys)
        let mut public_key = self.y_i;
        for broad in self.round2_broad.values() {
            public_key += broad.y_i;
        }

        let public_shares = self.compute_public_shares();

        // Build auxiliary data for Fiat-Shamir challenge: empty (GG18 uses empty aux)
        let aux = [0u8; 0];

        // Generate Schnorr DLog proof for X_i = x_i * G
        let own_public_share = public_shares[(my_index - 1) as usize];
        let schnorr_proof =
            DlogProof::<C>::prove(&x_i, &self.schnorr_ephemeral, &own_public_share, &aux);

        // Generate Pi_mod proof: prove that our Paillier modulus N is a
        // Paillier-Blum modulus (paper §4.1 Phase 3).
        let paillier_n = self.dk.n().clone();
        let pi_mod_data = pi_mod::Data { n: &paillier_n };
        let pi_mod_pdata = pi_mod::PrivateData {
            p: self.dk.p(),
            q: self.dk.q(),
        };
        let shared_state = "gg18-keygen-pi-mod";
        let mut pi_mod_rng = tecdsa_core::Csprng::new();
        let paillier_mod_proof =
            pi_mod::non_interactive::prove::<{ PI_MOD_SECURITY }, sha2::Sha256>(
                &shared_state,
                pi_mod_data,
                pi_mod_pdata,
                &mut pi_mod_rng,
            )
            .expect("Pi_mod proof generation must succeed for valid Paillier primes");

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18KeygenMsg::Round3(MsgRound3 {
                schnorr_proof,
                paillier_mod_proof,
            }),
        }];

        // Collect all parties' Paillier EKs and NTilde params
        let mut paillier_eks = Vec::with_capacity(self.total as usize);
        let mut n_tilde_params_all = Vec::with_capacity(self.total as usize);

        // We need to insert items in party order (1..=total)
        for pid_val in 1..=self.total {
            let pid = PartyId(pid_val);
            if pid == self.my_id {
                paillier_eks.push(self.ek.clone());
                n_tilde_params_all.push(self.n_tilde_params.clone());
            } else {
                let broad = self
                    .round2_broad
                    .get(&pid)
                    .expect("must have round2 broad from every other party");
                paillier_eks.push(broad.ek.clone());
                n_tilde_params_all.push(NTildeParams {
                    N_tilde: broad.n_tilde.0.clone(),
                    h1: broad.h1.0.clone(),
                    h2: broad.h2.0.clone(),
                });
            }
        }

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
            dk: self.dk,
            paillier_eks,
            n_tilde_params_all,
            outgoing,
            round3_msgs: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 3 state — DLog proof
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

    // Paillier keys
    pub dk: tecdsa_paillier::DecryptionKey,
    pub paillier_eks: Vec<tecdsa_paillier::EncryptionKey>,
    pub n_tilde_params_all: Vec<NTildeParams>,

    // Outgoing
    pub outgoing: Vec<Outgoing<Gg18KeygenMsg<C>>>,

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

    /// Verify all Schnorr proofs and Pi_mod proofs, produce the final `Gg18KeyShare`.
    pub fn finish(self) -> tecdsa_core::Result<Gg18KeyShare<C>> {
        let aux = [0u8; 0];
        let mut pi_mod_rng = tecdsa_core::Csprng::new();
        let shared_state = "gg18-keygen-pi-mod";

        // Verify every other party's Schnorr proof and Pi_mod proof
        for (&pid, msg) in &self.round3_msgs {
            let party_public_share = self.public_shares[(pid.0 - 1) as usize];
            if !msg.schnorr_proof.verify(&party_public_share, &aux) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} Schnorr proof verification failed"
                )));
            }

            // Verify Pi_mod proof: the party's Paillier modulus N is a Blum modulus
            let party_paillier_n = self.paillier_eks[(pid.0 - 1) as usize].n();
            let pi_mod_data = pi_mod::Data {
                n: party_paillier_n,
            };
            pi_mod::non_interactive::verify::<{ PI_MOD_SECURITY }, sha2::Sha256>(
                &shared_state,
                pi_mod_data,
                &msg.paillier_mod_proof,
                &mut pi_mod_rng,
            )
            .map_err(|e| {
                TecdsaError::InvalidProof(format!(
                    "party {pid} Pi_mod proof verification failed: {e}"
                ))
            })?;
        }

        // Party index is 0-based in Gg18KeyShare
        let party_index = self.my_id.0 - 1;

        Ok(Gg18KeyShare {
            party_index,
            secret_share: self.secret_share,
            public_key: self.public_key,
            public_shares: self.public_shares,
            vss_setup: VssSetup {
                threshold: self.threshold,
                total: self.total,
            },
            dk: self.dk,
            paillier_eks: self.paillier_eks,
            n_tilde_params: self.n_tilde_params_all,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the data to be committed (and later verified) in the hash commitment.
///
/// Format: `y_i_bytes || ek_N_bytes || N'_bytes || h1_bytes || h2_bytes || feldman_com_bytes...`
fn build_commit_data<C: TecdsaCurve>(
    y_i: &C::ProjectivePoint,
    ek: &tecdsa_paillier::EncryptionKey,
    ntilde: &NTildeParams,
    feldman_commitments: &[C::ProjectivePoint],
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut data = Vec::new();
    data.extend_from_slice(y_i.to_bytes().as_ref());
    data.extend_from_slice(&ek.n().to_bytes_msf());
    data.extend_from_slice(&ntilde.N_tilde.to_bytes_msf());
    data.extend_from_slice(&ntilde.h1.to_bytes_msf());
    data.extend_from_slice(&ntilde.h2.to_bytes_msf());
    for com in feldman_commitments {
        data.extend_from_slice(com.to_bytes().as_ref());
    }
    data
}
