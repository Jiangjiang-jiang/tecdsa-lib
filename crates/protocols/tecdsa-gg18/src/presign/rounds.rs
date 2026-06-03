// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for GG18 presigning (Phases 1-4).
//!
//! The presign protocol has 3 message rounds:
//!
//! 1. **Round 1 (Phase 1+2a merged):** Broadcast Com(g_gamma_i) + P2P c_A with AliceProof.
//! 2. **Round 2 (Phase 2b):** P2P: Bob responds with c_b + BobProofExt.
//! 3. **Round 3 (Phase 3+4 merged):** Broadcast delta_i + decommit g_gamma_i + Schnorr proof, compute R.
//!
//! After Round 3, each party has R, r, k_i, sigma_i -- the presignature.
//!
//! # Proof system abstraction
//!
//! GG18 uses `Gg18Proofs` from `tecdsa_paillier::mta` for Alice's range proofs
//! (via the `PaillierMtaProofs` trait), and `BobProofExt` directly for Bob's
//! extended range proofs (which include EC point verification not expressible
//! through the trait).
//!
//! GG18 uses inline Paillier operations rather than the full `MtA` trait because:
//!
//! 1. **1-to-N broadcast with shared ciphertext.** Alice encrypts k_i once and
//!    sends the same c_a to all peers. Each Bob runs *two* MtA instances on
//!    this c_a: one with gamma_j (for delta) and one with w_j (for sigma).
//!
//! 2. **Deferred proof verification.** Bob's gamma range proof cannot be
//!    verified until Round 3 (when g_gamma_j is decommitted).

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    backend::Integer,
    conv::{integer_to_scalar, scalar_to_integer},
    mta::{Gg18ProofSetup, Gg18Proofs, PaillierMtaProofs},
    zk::mta_range::BobProofExt,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use tecdsa_vss::lagrange;
use zeroize::Zeroize;

use super::types::Gg18Presignature;
use crate::{
    key_share::Gg18KeyShare,
    sign::{msg::*, sign_keys::SignKeys},
};

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Gg18Presignature<C>),
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Presign session configuration
// ---------------------------------------------------------------------------

/// Configuration for a presigning session (message-independent).
pub struct PresignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The key share from keygen.
    pub key_share: Gg18KeyShare<C>,
    /// The signing subset (1-based party indices).
    pub signers: Vec<u16>,
}

/// Shared state carried across all presigning rounds.
#[allow(dead_code)]
struct SharedState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    key_share: Gg18KeyShare<C>,
    signers: Vec<u16>,
    sign_keys: SignKeys<C>,
}

// ---------------------------------------------------------------------------
// Round 1: Phase 1 + Phase 2a merged -- commit g_gamma_i + MtA Alice
// ---------------------------------------------------------------------------

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    decommit_nonce: [u8; 32],
    /// Schnorr ephemeral for the gamma_i proof (used in Round 3).
    gamma_schnorr_eph: C::Scalar,
    /// Our c_a ciphertext (stored for potential proof verification).
    #[allow(dead_code)]
    c_a: Integer,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    round1_p2ps: BTreeMap<PartyId, MsgSignRound1P2p>,
    /// Bob's beta shares from handling Alice messages in Round 1.
    beta_shares: BTreeMap<PartyId, C::Scalar>,
    /// Bob's nu shares from handling Alice messages in Round 1.
    nu_shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: PresignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let my_1based = config.key_share.party_index + 1;
        let my_id = PartyId(my_1based);
        let signer_parties: Vec<PartyId> = config.signers.iter().map(|&i| PartyId(i)).collect();

        // Compute Lagrange coefficient
        let lagrange_coeffs = lagrange::coefficients::<C>(&config.signers);
        let my_signer_pos = config
            .signers
            .iter()
            .position(|&i| i == my_1based)
            .expect("this party must be in the signing subset");
        let lambda_i = lagrange_coeffs[my_signer_pos];

        let sign_keys = SignKeys::create(&config.key_share.secret_share, &lambda_i, rng);

        // Commit to g_gamma_i
        let commit_data = point_to_bytes::<C>(&sign_keys.g_gamma_i);
        let (commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        // Schnorr ephemeral for gamma_i proof (used in Round 3)
        let gamma_schnorr_eph = C::random_scalar(rng);

        // Encrypt k_i for MtA Alice messages.
        let my_idx = (my_id.0 - 1) as usize;
        let my_ek = &config.key_share.paillier_eks[my_idx];
        let k_i_int = scalar_to_integer::<C>(&sign_keys.k_i);
        let (c_a, r_a) = my_ek
            .encrypt_with_random(rng, &k_i_int)
            .expect("Paillier encrypt must succeed");

        // Build outgoing messages:
        // 1. Broadcast: commitment to g_gamma_i
        let mut outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round1Broadcast(MsgSignRound1Broadcast { commitment }),
        }];

        // 2. P2P to each peer: c_a + AliceProof
        //    Alice proof uses the RECEIVER's N_tilde params via Gg18Proofs.
        for &pid in &signer_parties {
            if pid == my_id {
                continue;
            }
            // Alice proof uses the RECEIVER's N-tilde params
            let receiver_ntilde = &config.key_share.n_tilde_params[(pid.0 - 1) as usize];
            let proof_setup = Gg18ProofSetup {
                ntilde: receiver_ntilde.clone(),
            };
            let q_dummy = Integer::zero(); // q is derived internally by Gg18Proofs
            let alice_proof =
                Gg18Proofs::prove_sender(my_ek, &k_i_int, &c_a, &r_a, &proof_setup, &q_dummy, rng);
            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Gg18SignMsg::Round1P2p(MsgSignRound1P2p {
                    c_a: crate::keygen::msg::SerInteger(c_a.clone()),
                    alice_proof,
                }),
            });
        }

        Self {
            shared: SharedState {
                my_id,
                signer_parties,
                key_share: config.key_share,
                signers: config.signers,
                sign_keys,
            },
            decommit_nonce,
            gamma_schnorr_eph,
            c_a,
            outgoing,
            round1_broadcasts: BTreeMap::new(),
            round1_p2ps: BTreeMap::new(),
            beta_shares: BTreeMap::new(),
            nu_shares: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle_broadcast(
        &mut self,
        from: PartyId,
        msg: MsgSignRound1Broadcast,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round1_broadcasts.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_broadcasts.insert(from, msg);
        Ok(())
    }

    pub fn handle_p2p(
        &mut self,
        from: PartyId,
        msg: MsgSignRound1P2p,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round1_p2ps.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }

        // Verify Alice's range proof using OUR N_tilde params via Gg18Proofs
        let my_idx = (self.shared.my_id.0 - 1) as usize;
        let my_ntilde = &self.shared.key_share.n_tilde_params[my_idx];
        let sender_ek = &self.shared.key_share.paillier_eks[(from.0 - 1) as usize];

        let proof_setup = Gg18ProofSetup {
            ntilde: my_ntilde.clone(),
        };
        let q_dummy = Integer::zero();
        if !Gg18Proofs::verify_sender(
            sender_ek,
            &msg.c_a.0,
            &msg.alice_proof,
            &proof_setup,
            &q_dummy,
        ) {
            return Err(TecdsaError::InvalidProof(format!(
                "party {from} Alice range proof verification failed"
            )));
        }

        // Bob's role: compute c_b for both MtA protocols.
        // Uses direct Paillier homomorphic operations (omul + oadd) with
        // GG18-specific BobProofExt range proofs (which require EC point
        // data not expressible through the PaillierMtaProofs trait).
        let c_a_j = &msg.c_a.0;
        let sender_ntilde = &self.shared.key_share.n_tilde_params[(from.0 - 1) as usize];

        // MtA for (k_j, gamma_i):
        let gamma_i_int = scalar_to_integer::<C>(&self.shared.sign_keys.gamma_i);
        let beta_prim = sender_ek.half_n().random_below_ref(rng);
        let r_bob_gamma = Integer::sample_in_mult_group_of(rng, sender_ek.n());

        let b_times_ca = sender_ek.omul(&gamma_i_int, c_a_j).expect("omul");
        let enc_beta = sender_ek
            .encrypt_with(&beta_prim, &r_bob_gamma)
            .expect("encrypt beta");
        let c_b_gamma = sender_ek.oadd(&b_times_ca, &enc_beta).expect("oadd");

        // MtA for (k_j, w_i):
        let w_i_int = scalar_to_integer::<C>(&self.shared.sign_keys.w_i);
        let nu_prim = sender_ek.half_n().random_below_ref(rng);
        let r_bob_w = Integer::sample_in_mult_group_of(rng, sender_ek.n());

        let w_times_ca = sender_ek.omul(&w_i_int, c_a_j).expect("omul");
        let enc_nu = sender_ek
            .encrypt_with(&nu_prim, &r_bob_w)
            .expect("encrypt nu");
        let c_b_w = sender_ek.oadd(&w_times_ca, &enc_nu).expect("oadd");

        // Generate Bob's extended proofs (BobProofExt includes EC DLog check)
        let bob_proof_gamma = BobProofExt::<C>::prove(
            c_a_j,
            &c_b_gamma,
            &gamma_i_int,
            &beta_prim,
            sender_ek.n(),
            sender_ek.nn(),
            sender_ntilde,
            &r_bob_gamma,
            rng,
        );

        let bob_proof_w = BobProofExt::<C>::prove(
            c_a_j,
            &c_b_w,
            &w_i_int,
            &nu_prim,
            sender_ek.n(),
            sender_ek.nn(),
            sender_ntilde,
            &r_bob_w,
            rng,
        );

        // Store Bob's shares: beta = -beta_prim, nu = -nu_prim
        let neg_beta_scalar = -integer_to_scalar::<C>(&beta_prim);
        let neg_nu_scalar = -integer_to_scalar::<C>(&nu_prim);
        self.beta_shares.insert(from, neg_beta_scalar);
        self.nu_shares.insert(from, neg_nu_scalar);

        // Compute w_i * G for the proof (Bob's claimed public point)
        let w_i_scalar = integer_to_scalar::<C>(&w_i_int);
        let w_j_point = C::generator() * w_i_scalar;

        // Queue Bob response to Alice
        self.outgoing.push(Outgoing {
            to: Recipient::Party(from),
            msg: Gg18SignMsg::Round2(MsgSignRound2 {
                c_b_gamma: crate::keygen::msg::SerInteger(c_b_gamma),
                c_b_w: crate::keygen::msg::SerInteger(c_b_w),
                bob_proof_gamma,
                bob_proof_w,
                w_j_point,
            }),
        });

        self.round1_p2ps.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round1_broadcasts.len() == self.expected_count()
            && self.round1_p2ps.len() == self.expected_count()
    }

    /// Transition to Round 2: wait for Bob responses.
    pub fn advance(mut self) -> Round2State<C> {
        // Collect beta and nu shares in signer order
        let mut beta_vec = Vec::new();
        let mut nu_vec = Vec::new();
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            beta_vec.push(self.beta_shares[&pid]);
            nu_vec.push(self.nu_shares[&pid]);
        }

        // Zeroize secret shares not carried to the next round
        for v in self.beta_shares.values_mut() {
            v.zeroize();
        }
        for v in self.nu_shares.values_mut() {
            v.zeroize();
        }

        Round2State {
            shared: self.shared,
            decommit_nonce: self.decommit_nonce,
            gamma_schnorr_eph: self.gamma_schnorr_eph,
            round1_broadcasts: self.round1_broadcasts,
            c_a: self.c_a,
            beta_vec,
            nu_vec,
            outgoing: self.outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2: receive Bob responses, decrypt to get alpha/mu shares
// ---------------------------------------------------------------------------

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    decommit_nonce: [u8; 32],
    gamma_schnorr_eph: C::Scalar,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    c_a: Integer,
    beta_vec: Vec<C::Scalar>,
    nu_vec: Vec<C::Scalar>,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round2_msgs: BTreeMap<PartyId, MsgSignRound2<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgSignRound2<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round2_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }

        // Verify Bob's w range proof (BobProofExt with EC check -- immediate)
        let my_ek = &self.shared.key_share.paillier_eks[(self.shared.my_id.0 - 1) as usize];
        let my_ntilde = &self.shared.key_share.n_tilde_params[(self.shared.my_id.0 - 1) as usize];

        msg.bob_proof_w
            .verify(
                &self.c_a,
                &msg.c_b_w.0,
                my_ek.n(),
                my_ek.nn(),
                my_ntilde,
                &msg.w_j_point,
            )
            .map_err(|e| {
                TecdsaError::InvalidProof(format!("party {from} Bob w range proof failed: {e}"))
            })?;

        // bob_proof_gamma deferred: gamma_j*G not yet revealed (committed in Round 1).
        self.round2_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_msgs.len() == self.expected_count()
    }

    /// Decrypt Bob responses, compute delta_i and sigma_i, transition to Round 3.
    pub fn advance(mut self) -> Round3State<C> {
        // Alice's role: decrypt each c_b
        let mut alpha_vec = Vec::new();
        let mut mu_vec = Vec::new();

        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            let bob_msg = &self.round2_msgs[&pid];

            let alpha_int = self
                .shared
                .key_share
                .dk
                .decrypt(&bob_msg.c_b_gamma.0)
                .expect("decrypt c_b_gamma");
            let alpha = signed_integer_to_scalar::<C>(&alpha_int);
            alpha_vec.push(alpha);

            let mu_int = self
                .shared
                .key_share
                .dk
                .decrypt(&bob_msg.c_b_w.0)
                .expect("decrypt c_b_w");
            let mu = signed_integer_to_scalar::<C>(&mu_int);
            mu_vec.push(mu);
        }

        // Compute delta_i and sigma_i
        let delta_i = self
            .shared
            .sign_keys
            .compute_delta_i(&alpha_vec, &self.beta_vec);
        let sigma_i = self.shared.sign_keys.compute_sigma_i(&mu_vec, &self.nu_vec);

        // Build Round 3 message: delta_i + decommit g_gamma_i + Schnorr proof for gamma_i
        let gamma_proof = DlogProof::<C>::prove(
            &self.shared.sign_keys.gamma_i,
            &self.gamma_schnorr_eph,
            &self.shared.sign_keys.g_gamma_i,
            &[],
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round3(MsgSignRound3 {
                delta_i,
                g_gamma_i: self.shared.sign_keys.g_gamma_i,
                decommit_nonce: self.decommit_nonce,
                gamma_proof,
            }),
        }];

        // Zeroize secrets not carried to the next round
        self.gamma_schnorr_eph.zeroize();
        for s in &mut self.beta_vec {
            s.zeroize();
        }
        for s in &mut self.nu_vec {
            s.zeroize();
        }

        Round3State {
            shared: self.shared,
            round1_broadcasts: self.round1_broadcasts,
            c_a: self.c_a,
            round2_bob_msgs: self.round2_msgs,
            delta_i,
            sigma_i,
            outgoing,
            round3_msgs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 3: Phase 3+4 merged -- delta + decommit + Schnorr verify, compute R
// ---------------------------------------------------------------------------

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    c_a: Integer,
    round2_bob_msgs: BTreeMap<PartyId, MsgSignRound2<C>>,
    delta_i: C::Scalar,
    sigma_i: C::Scalar,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round3_msgs: BTreeMap<PartyId, MsgSignRound3<C>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgSignRound3<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round3_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round3_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round3_msgs.len() == self.expected_count()
    }

    /// Verify decommitments, Schnorr proofs, compute R, and produce the presignature.
    pub fn finish(mut self) -> tecdsa_core::Result<Gg18Presignature<C>> {
        // Verify all decommitments and Schnorr proofs
        for (&pid, decom) in &self.round3_msgs {
            let commit = self.round1_broadcasts.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round1 broadcast from {pid}"))
            })?;

            // Verify hash commitment for g_gamma_i
            let commit_data = decom.g_gamma_i.to_bytes();
            if !commit
                .commitment
                .verify(commit_data.as_ref(), &decom.decommit_nonce)
            {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} g_gamma_i decommitment failed"
                )));
            }

            // Verify Schnorr proof for gamma_i
            if !decom.gamma_proof.verify(&decom.g_gamma_i, &[]) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} Schnorr proof for gamma_i failed"
                )));
            }

            // Deferred verification: Bob's gamma range proof (from Round 2)
            // Now that g_gamma_j is revealed, we can verify BobProofExt
            // which includes EC DLog verification.
            if let Some(bob_msg) = self.round2_bob_msgs.get(&pid) {
                let my_ek = &self.shared.key_share.paillier_eks[(self.shared.my_id.0 - 1) as usize];
                let my_ntilde =
                    &self.shared.key_share.n_tilde_params[(self.shared.my_id.0 - 1) as usize];
                bob_msg
                    .bob_proof_gamma
                    .verify(
                        &self.c_a,
                        &bob_msg.c_b_gamma.0,
                        my_ek.n(),
                        my_ek.nn(),
                        my_ntilde,
                        &decom.g_gamma_i,
                    )
                    .map_err(|e| {
                        TecdsaError::InvalidProof(format!(
                            "party {pid} Bob gamma range proof failed: {e}"
                        ))
                    })?;
            }
        }

        // Collect all g_gamma_i and delta_i
        let mut g_gamma_vec = vec![self.shared.sign_keys.g_gamma_i];
        let mut all_deltas = vec![self.delta_i];
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            g_gamma_vec.push(self.round3_msgs[&pid].g_gamma_i);
            all_deltas.push(self.round3_msgs[&pid].delta_i);
        }

        // Compute delta_inv and R
        let delta_inv = SignKeys::<C>::reconstruct_delta_inv(&all_deltas)?;
        let (R, r) = SignKeys::<C>::compute_R(&delta_inv, &g_gamma_vec);

        // Zeroize secrets not included in the presignature output
        self.delta_i.zeroize();

        Ok(Gg18Presignature {
            R,
            r,
            k_i: self.shared.sign_keys.k_i,
            sigma_i: self.sigma_i,
            public_key: self.shared.key_share.public_key,
            my_id: self.shared.my_id,
            signer_parties: self.shared.signer_parties.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize a projective point to bytes.
fn point_to_bytes<C: TecdsaCurve>(p: &C::ProjectivePoint) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    p.to_bytes().as_ref().to_vec()
}

/// Convert a Paillier `Integer` (which may be negative) to an EC scalar mod q.
fn signed_integer_to_scalar<C: TecdsaCurve>(
    i: &Integer,
) -> <C as elliptic_curve::CurveArithmetic>::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if i.cmp0().is_lt() {
        let abs_val = -i.clone();
        let pos_scalar = integer_to_scalar::<C>(&abs_val);
        -pos_scalar
    } else {
        integer_to_scalar::<C>(i)
    }
}

fn validate_sender(from: PartyId, my_id: PartyId, parties: &[PartyId]) -> tecdsa_core::Result<()> {
    if from == my_id {
        return Err(TecdsaError::Other("received message from self".into()));
    }
    if !parties.contains(&from) {
        return Err(TecdsaError::UnknownSender(from.0));
    }
    Ok(())
}
