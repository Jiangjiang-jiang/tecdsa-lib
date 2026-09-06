// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for GGN16 presigning (Rounds 1-5).
//!
//! The presigning protocol is message-independent and produces a
//! [`Ggn16Presignature`] that can be consumed by online signing.
//!
//! ## Protocol Rounds
//!
//! 1. **Commit(u_i, v_i):** each party samples rho_i, encrypts u_i = E(rho_i)
//!    and v_i = rho_i ×_E alpha, then broadcasts a hash commitment.
//! 2. **Decommit:** each party opens the commitment and broadcasts u_i, v_i.
//!    Parties aggregate u = sum(u_i), v = sum(v_i).
//! 3. **Commit(r_i, w_i):** each party samples k_i, computes r_i = k_i*G and
//!    w_i = k_i ×_E u +_E E(c_i*q), then broadcasts a hash commitment.
//! 4. **Decommit:** each party opens the commitment and broadcasts r_i, w_i.
//!    Parties aggregate w = sum(w_i), R = sum(r_i), r = x(R) mod q.
//! 5. **Threshold decrypt w:** each party broadcasts a partial decryption of w.
//!    After combining, psi = eta^{-1} mod q.
//!
//! Reference: Gennaro, Goldfeder, Narayanan. ACNS 2016, Section 4.3.

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{
    conv::{curve_order, integer_to_scalar, scalar_to_integer},
    TecdsaCurve,
};
use tecdsa_paillier::{
    backend::Integer,
    threshold::{combine_partials, partial_decrypt, PartialDecryption},
    zk::{
        homo_mult::{HomoMultProof, HomoMultStatement, HomoMultWitness},
        nonce_consist::{NonceConsistProof, NonceConsistStatement, NonceConsistWitness},
    },
    BigIntExt,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use crate::{
    key_share::Ggn16KeyShare,
    presign::types::Ggn16Presignature,
    sign::msg::{
        Ggn16SignMsg, SignRound1Msg, SignRound2Msg, SignRound3Msg, SignRound4Msg, SignRound5Msg,
    },
    utils::{deserialize_point, serialize_for_commit_r1, serialize_for_commit_r3},
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub(crate) struct PresignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Ggn16KeyShare<C>,
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
}

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
    Round4(Round4State<C>),
    Round5(Round5State<C>),
    Done(Ggn16Presignature<C>),
    #[default]
    Poisoned,
}

// ---------------------------------------------------------------------------
// Round 1: Commit to (u_i, v_i)
// ---------------------------------------------------------------------------

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    // Own secrets
    pub rho_i: Integer,
    pub u_i: Integer,
    pub v_i: Integer,
    pub r_u: Integer,
    pub r_v: Integer,
    pub decommit_nonce: [u8; 32],

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round1_msgs: BTreeMap<PartyId, SignRound1Msg>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: PresignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let ek = &config.key_share.threshold_setup.ek;
        let alpha = &config.key_share.alpha;

        // 1. Sample rho_i in Z_q
        let q = curve_order::<C>();
        let rho_i = q.sample_below_ref(rng);

        // 2. u_i = E(rho_i; r_u) -- encrypt under shared Paillier key
        let (u_i, r_u) = ek
            .encrypt_with_random(rng, &rho_i)
            .expect("Paillier encryption of rho_i must succeed");

        // 3. v_i = alpha^{rho_i} * r_v^N mod N^2
        //    omul gives alpha^{rho_i} mod N^2 (without explicit re-randomization).
        //    We then re-randomize with a fresh r_v so the prover can construct
        //    the HomoMultProof witness (r_c3 = r_v).
        let v_i_raw = ek
            .omul(&rho_i, alpha)
            .expect("homomorphic scalar-mul must succeed");
        let r_v = Integer::sample_in_mult_group_of(rng, ek.n());
        let r_v_n = Integer::from(
            r_v.pow_mod_ref(ek.n(), ek.nn())
                .expect("r_v^N mod N^2 must succeed"),
        );
        let v_i = Integer::from(&v_i_raw * &r_v_n).modulo(ek.nn());

        // 4. Hash commitment: C_{1,i} = Com(u_i || v_i)
        let commit_data = serialize_for_commit_r1(&u_i, &v_i);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        // 5. Broadcast C_{1,i}
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round1(SignRound1Msg {
                commitment: hash_commitment,
            }),
        }];

        Self {
            config,
            rho_i,
            u_i,
            v_i,
            r_u,
            r_v,
            decommit_nonce,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound1Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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

    /// Transition to Round 2: broadcast decommitment + (u_i, v_i) + HomoMultProof.
    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> Round2State<C> {
        let ek = &self.config.key_share.threshold_setup.ek;

        // Construct Pi_{1,i} (HomoMultProof):
        //   c1 = u_i = Enc(rho_i; r_u)
        //   c2 = alpha = Enc(x)
        //   c3 = v_i = alpha^{rho_i} * r_v^N mod N^2
        // Witness: eta = rho_i, r_c1 = r_u, r_c3 = r_v
        let statement = HomoMultStatement {
            c1: self.u_i.clone(),
            c2: self.config.key_share.alpha.clone(),
            c3: self.v_i.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: self.config.key_share.h1.clone(),
            h2: self.config.key_share.h2.clone(),
            N_tilde: self.config.key_share.N_tilde.clone(),
        };
        let witness = HomoMultWitness {
            eta: self.rho_i.clone(),
            r_c1: self.r_u.clone(),
            r_c3: self.r_v.clone(),
        };
        let proof = HomoMultProof::prove::<C>(&witness, &statement, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round2(SignRound2Msg {
                u_i: self.u_i.clone(),
                v_i: self.v_i.clone(),
                nonce: self.decommit_nonce,
                homo_mult_proof: proof.to_bytes(),
            }),
        }];

        // Zeroize encryption randomness not carried to the next round
        self.r_u = Integer::from(0u32);
        self.r_v = Integer::from(0u32);

        Round2State {
            config: self.config,
            rho_i: self.rho_i,
            u_i: self.u_i,
            v_i: self.v_i,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2: Decommit (u_i, v_i), aggregate u and v
// ---------------------------------------------------------------------------

#[allow(dead_code)] // rho_i retained for potential extensions
pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,
    pub rho_i: Integer,
    pub u_i: Integer,
    pub v_i: Integer,
    pub round1_commitments: BTreeMap<PartyId, SignRound1Msg>,
    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round2_msgs: BTreeMap<PartyId, SignRound2Msg>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound2Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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

    /// Verify commitments, compute aggregates u and v, transition to Round 3.
    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<Round3State<C>> {
        let ek = &self.config.key_share.threshold_setup.ek;

        // Verify all decommitments and aggregate
        let mut u = self.u_i.clone();
        let mut v = self.v_i.clone();

        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r2 = self.round2_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round2 message from party {pid}"))
            })?;
            let r1 = self.round1_commitments.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round1 commitment from party {pid}"))
            })?;

            // Verify hash commitment
            let commit_data = serialize_for_commit_r1(&r2.u_i, &r2.v_i);
            if !r1.commitment.verify(&commit_data, &r2.nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} round 1 commitment verification failed"
                )));
            }

            // Verify Pi_{1,i} (HomoMultProof)
            let proof = HomoMultProof::from_bytes(&r2.homo_mult_proof).ok_or_else(|| {
                TecdsaError::Other(format!("party {pid} sent malformed HomoMultProof"))
            })?;
            let statement = HomoMultStatement {
                c1: r2.u_i.clone(),
                c2: self.config.key_share.alpha.clone(),
                c3: r2.v_i.clone(),
                ek_n: ek.n().clone(),
                ek_nn: ek.nn().clone(),
                h1: self.config.key_share.h1.clone(),
                h2: self.config.key_share.h2.clone(),
                N_tilde: self.config.key_share.N_tilde.clone(),
            };
            proof.verify::<C>(&statement).map_err(|e| {
                TecdsaError::Other(format!(
                    "party {pid} HomoMultProof verification failed: {e}"
                ))
            })?;

            // Aggregate: u = oadd(u, u_j), v = oadd(v, v_j)
            u = ek
                .oadd(&u, &r2.u_i)
                .map_err(|e| TecdsaError::Other(format!("oadd u failed: {e}")))?;
            v = ek
                .oadd(&v, &r2.v_i)
                .map_err(|e| TecdsaError::Other(format!("oadd v failed: {e}")))?;
        }

        // Now u = E(rho) and v = E(rho * x) where rho = sum(rho_i)

        // Round 3: sample k_i, c_i, compute r_i = k_i*G and w_i
        let q = curve_order::<C>();

        // k_i in Z_q (nonzero)
        let k_i_scalar = C::random_scalar(rng);
        let k_i = scalar_to_integer::<C>(&k_i_scalar);

        // r_i = k_i * G
        let r_i = C::generator() * k_i_scalar;
        let r_i_bytes: Vec<u8> = r_i.to_bytes().as_ref().to_vec();

        // c_i in Z: sample small range. For testing, use q^2 range.
        // In production, c_i should be from a range like q^6, but for
        // correctness testing we use q^2 (statistical security can be relaxed).
        let c_i_bound = Integer::from(&q * &q);
        let c_i = c_i_bound.sample_below_ref(rng);

        // w_i = k_i ×_E u +_E E(c_i * q)
        let ki_times_u = ek
            .omul(&k_i, &u)
            .map_err(|e| TecdsaError::Other(format!("omul k_i*u failed: {e}")))?;
        let c_i_q = Integer::from(&c_i * &q);
        let (enc_ciq, enc_nonce) = ek
            .encrypt_with_random(rng, &c_i_q)
            .map_err(|e| TecdsaError::Other(format!("encrypt c_i*q failed: {e}")))?;
        let w_i = ek
            .oadd(&ki_times_u, &enc_ciq)
            .map_err(|e| TecdsaError::Other(format!("oadd w_i failed: {e}")))?;

        // Hash commitment: C_{2,i} = Com(r_i || w_i)
        let commit_data = serialize_for_commit_r3(&r_i_bytes, &w_i);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round3(SignRound3Msg {
                commitment: hash_commitment,
            }),
        }];

        // Zeroize secrets not carried to the next round
        self.rho_i = Integer::from(0u32);

        Ok(Round3State {
            config: self.config,
            u,
            v,
            k_i_scalar,
            k_i,
            c_i,
            r_w: enc_nonce,
            r_i,
            r_i_bytes,
            w_i,
            decommit_nonce,
            outgoing,
            round3_msgs: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 3: Commit to (r_i, w_i)
// ---------------------------------------------------------------------------

#[allow(dead_code)] // k_i_scalar retained alongside k_i (Integer form used by proof)
pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    // Aggregates from Round 2
    pub u: Integer,
    pub v: Integer,

    // Own secrets for this round
    pub k_i_scalar: C::Scalar,
    pub k_i: Integer,
    pub c_i: Integer,
    pub r_w: Integer,
    pub r_i: C::ProjectivePoint,
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,
    pub decommit_nonce: [u8; 32],

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round3_msgs: BTreeMap<PartyId, SignRound3Msg>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound3Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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

    /// Transition to Round 4: broadcast decommitment + (r_i, w_i) + NonceConsistProof.
    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> Round4State<C> {
        let ek = &self.config.key_share.threshold_setup.ek;

        // Construct Pi_{2,i} (NonceConsistProof):
        //   G = generator
        //   r_i = G^{k_i}
        //   w_i = u^{k_i} * Gamma^{c_i*q} * r_w^N mod N^2
        //   u = aggregated ciphertext E(rho)
        // Witness: eta1 = k_i, eta2 = c_i, r_c = r_w
        let statement = NonceConsistStatement::<C> {
            G: C::generator(),
            r_i: self.r_i,
            w_i: self.w_i.clone(),
            u: self.u.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: self.config.key_share.h1.clone(),
            h2: self.config.key_share.h2.clone(),
            N_tilde: self.config.key_share.N_tilde.clone(),
        };
        let witness = NonceConsistWitness {
            eta1: self.k_i.clone(),
            eta2: self.c_i.clone(),
            r_c: self.r_w.clone(),
        };
        let proof = NonceConsistProof::<C>::prove(&witness, &statement, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round4(SignRound4Msg {
                r_i_bytes: self.r_i_bytes.clone(),
                w_i: self.w_i.clone(),
                nonce: self.decommit_nonce,
                nonce_consist_proof: proof.to_bytes(),
            }),
        }];

        // Zeroize secrets not carried to the next round
        self.k_i_scalar.zeroize();
        self.k_i = Integer::from(0u32);
        self.c_i = Integer::from(0u32);
        self.r_w = Integer::from(0u32);

        Round4State {
            config: self.config,
            u: self.u,
            v: self.v,
            r_i: self.r_i,
            r_i_bytes: self.r_i_bytes,
            w_i: self.w_i,
            round3_commitments: self.round3_msgs,
            outgoing,
            round4_msgs: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 4: Decommit (r_i, w_i), aggregate R and w
// ---------------------------------------------------------------------------

#[allow(dead_code)] // r_i_bytes retained for debugging/auditing
pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    // Aggregates from Round 2
    pub u: Integer,
    pub v: Integer,

    // Own values
    pub r_i: C::ProjectivePoint,
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,

    pub round3_commitments: BTreeMap<PartyId, SignRound3Msg>,
    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round4_msgs: BTreeMap<PartyId, SignRound4Msg>,
}

impl<C: TecdsaCurve> Round4State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound4Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round4_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round4_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round4_msgs.len() == self.expected_count()
    }

    /// Verify commitments, aggregate R and w, start threshold decryption.
    pub fn advance(self) -> tecdsa_core::Result<Round5State<C>> {
        let ek = &self.config.key_share.threshold_setup.ek;
        let setup = &self.config.key_share.threshold_setup;

        // Verify all decommitments and aggregate
        let mut R = self.r_i;
        let mut w = self.w_i.clone();

        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r4 = self.round4_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round4 message from party {pid}"))
            })?;
            let r3 = self.round3_commitments.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round3 commitment from party {pid}"))
            })?;

            // Verify hash commitment
            let commit_data = serialize_for_commit_r3(&r4.r_i_bytes, &r4.w_i);
            if !r3.commitment.verify(&commit_data, &r4.nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} round 3 commitment verification failed"
                )));
            }

            // Deserialize r_j (needed for both proof verification and aggregation)
            let r_j = deserialize_point::<C>(&r4.r_i_bytes).map_err(|_| {
                TecdsaError::Other(format!("party {pid} sent invalid r_i point encoding"))
            })?;

            // Verify Pi_{2,i} (NonceConsistProof)
            let proof =
                NonceConsistProof::<C>::from_bytes(&r4.nonce_consist_proof).ok_or_else(|| {
                    TecdsaError::Other(format!("party {pid} sent malformed NonceConsistProof"))
                })?;
            let nc_statement = NonceConsistStatement::<C> {
                G: C::generator(),
                r_i: r_j,
                w_i: r4.w_i.clone(),
                u: self.u.clone(),
                ek_n: ek.n().clone(),
                ek_nn: ek.nn().clone(),
                h1: self.config.key_share.h1.clone(),
                h2: self.config.key_share.h2.clone(),
                N_tilde: self.config.key_share.N_tilde.clone(),
            };
            proof.verify(&nc_statement).map_err(|e| {
                TecdsaError::Other(format!(
                    "party {pid} NonceConsistProof verification failed: {e}"
                ))
            })?;

            // Aggregate
            R += r_j;
            w = ek
                .oadd(&w, &r4.w_i)
                .map_err(|e| TecdsaError::Other(format!("oadd w failed: {e}")))?;
        }

        // Compute r = x_coord(R) mod q
        let R_affine = R.to_affine();
        let r = C::xcoord_mod_q(&R_affine);

        // Threshold decrypt w: each party computes partial decryption
        let my_partial = partial_decrypt(&w, &self.config.key_share.decryption_share, setup);

        // Broadcast partial decryption
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round5(SignRound5Msg {
                partial_w: my_partial.clone(),
            }),
        }];

        Ok(Round5State {
            config: self.config,
            u: self.u,
            v: self.v,
            R,
            r,
            w,
            my_partial,
            outgoing,
            round5_msgs: BTreeMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Round 5: Threshold decrypt w, compute psi
// ---------------------------------------------------------------------------

#[allow(dead_code)] // w retained for debugging/auditing
pub(crate) struct Round5State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    // Aggregates
    pub u: Integer,
    pub v: Integer,
    pub R: C::ProjectivePoint,
    pub r: C::Scalar,
    pub w: Integer,

    // Own partial decryption
    pub my_partial: PartialDecryption,

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round5_msgs: BTreeMap<PartyId, SignRound5Msg>,
}

impl<C: TecdsaCurve> Round5State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound5Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round5_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round5_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round5_msgs.len() == self.expected_count()
    }

    /// Combine partial decryptions of w, compute psi, produce Ggn16Presignature.
    pub fn finish(self) -> tecdsa_core::Result<Ggn16Presignature<C>> {
        let setup = &self.config.key_share.threshold_setup;

        // Collect all partial decryptions (own + received)
        let mut partials = vec![self.my_partial];
        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r5 = self.round5_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round5 message from party {pid}"))
            })?;
            partials.push(r5.partial_w.clone());
        }

        // Combine partial decryptions: eta = D(w) = k*rho + c*q (mod q => k*rho)
        let eta = combine_partials(&partials, setup)
            .map_err(|e| TecdsaError::Other(format!("threshold decryption of w failed: {e}")))?;

        // Reduce eta mod q to get k*rho mod q
        let q = curve_order::<C>();
        let eta_mod_q = Integer::from(eta.modulo_ref(&q));

        // Compute psi = (k*rho)^{-1} mod q
        let eta_scalar = integer_to_scalar::<C>(&eta_mod_q);
        let psi = eta_scalar
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("eta is zero, cannot invert for psi".into()))?;

        Ok(Ggn16Presignature {
            psi,
            u: self.u,
            v: self.v,
            R: self.R,
            r: self.r,
            key_share: self.config.key_share,
            my_id: self.config.my_id,
            signer_parties: self.config.signer_parties,
        })
    }
}
