// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for DKLs23 relaxed DKG.
//!
//! The protocol proceeds in 3 rounds:
//! 1. **Commit:** each party samples a degree-(t-1) polynomial, commits to
//!    the evaluation points X_{i,j} = p_i(j) * G via a hash commitment.
//! 2. **Decommit + Share:** each party broadcasts the decommitment (salt +
//!    points + P_i^*) and P2P sends Shamir share s_{i,j} = p_i(j) to each
//!    party j.
//! 3. **Verify + Compute:** each party verifies decommitments and share
//!    consistency (s_{i,j} * G == X_{i,j}), then computes its combined
//!    Shamir share and the joint public key.

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{PointExt, TecdsaCurve};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use super::msg::{Dkls23KeygenMsg, KeygenR1Broadcast, KeygenR2Broadcast, KeygenR2P2p};
use crate::{
    key_share::Dkls23KeyShare,
    utils::{scalar_from_canonical_bytes, validate_sender},
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a DKLs23 keygen participant.
pub(crate) struct KeygenConfig {
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
}

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
#[allow(dead_code)] // Round3 is never constructed directly; verification is inlined into Round2->Done
pub(crate) enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Dkls23KeyShare<C>),
    /// Sentinel so we can `std::mem::take` without leaving an invalid state.
    #[default]
    Poisoned,
}

// ---------------------------------------------------------------------------
// Round 1 state -- Commit
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
    /// Degree-(t-1) polynomial coefficients a_0, ..., a_{t-1}.
    pub poly_coeffs: Vec<C::Scalar>,
    /// P_i^* = p_i(0) * G = a_0 * G.
    pub p_i_star: C::ProjectivePoint,
    /// X_{i,j} = p_i(j) * G for j in [n] (1-indexed evaluation).
    pub x_ij_points: Vec<C::ProjectivePoint>,
    /// Salt used for the commitment hash.
    pub salt: [u8; 32],

    // Outgoing messages queued at construction
    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,

    // Received round 1 messages
    pub round1_msgs: BTreeMap<PartyId, KeygenR1Broadcast>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the initial Round 1 state: sample polynomial, compute
    /// commitments, and queue the Round 1 broadcast.
    pub fn new(config: KeygenConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.my_id;
        let parties = config.all_parties;
        let threshold = config.threshold;
        let total = config.total;

        // 1. Sample degree-(t-1) polynomial p_i(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
        let mut poly_coeffs = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            poly_coeffs.push(C::random_scalar(rng));
        }

        // 2. Compute P_i^* = p_i(0) * G = a_0 * G
        let p_i_star = C::generator() * poly_coeffs[0];

        // 3. Compute X_{i,j} = p_i(j) * G for j in 1..=n
        let mut x_ij_points = Vec::with_capacity(total as usize);
        for j in 1..=total {
            let p_i_j = evaluate_poly::<C>(&poly_coeffs, j);
            let x_ij = C::generator() * p_i_j;
            x_ij_points.push(x_ij);
        }

        // 4. Compute commitment hash: H(salt || X_{i,1} || ... || X_{i,n} || P_i^*)
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let commitment = compute_commitment::<C>(&salt, &x_ij_points, &p_i_star);

        // 5. Queue broadcast of Round 1 commitment
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23KeygenMsg::Round1Broadcast(KeygenR1Broadcast { commitment }),
        }];

        Self {
            my_id,
            parties,
            threshold,
            total,
            poly_coeffs,
            p_i_star,
            x_ij_points,
            salt,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: KeygenR1Broadcast) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.parties)?;
        if self.round1_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

    /// Transition to Round 2: queue broadcast decommitment + P2P shares.
    pub fn advance(self) -> Round2State<C> {
        // Serialize points for the broadcast
        let point_commitments: Vec<Vec<u8>> = self
            .x_ij_points
            .iter()
            .map(|pt| pt.to_bytes().as_ref().to_vec())
            .collect();
        let p_i_star_bytes = self.p_i_star.to_bytes().as_ref().to_vec();

        let mut outgoing = Vec::new();

        // 1. Broadcast decommitment: salt + all X_{i,j} + P_i^*
        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23KeygenMsg::Round2Broadcast(KeygenR2Broadcast {
                salt: self.salt,
                point_commitments,
                p_i_star: p_i_star_bytes,
            }),
        });

        // 2. P2P: send Shamir share s_{i,j} = p_i(j) to each party j
        for pid in &self.parties {
            if *pid == self.my_id {
                continue;
            }
            let j = pid.0; // 1-based party index
            let s_ij = evaluate_poly::<C>(&self.poly_coeffs, j);
            let repr = s_ij.to_repr();
            let share_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&repr).to_vec();
            outgoing.push(Outgoing {
                to: Recipient::Party(*pid),
                msg: Dkls23KeygenMsg::Round2P2p(KeygenR2P2p { share: share_bytes }),
            });
        }

        Round2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            poly_coeffs: self.poly_coeffs,
            p_i_star: self.p_i_star,
            x_ij_points: self.x_ij_points,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_broadcasts: BTreeMap::new(),
            round2_p2p: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2 state -- Decommit + Share
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

    // Own secrets
    pub poly_coeffs: Vec<C::Scalar>,
    pub p_i_star: C::ProjectivePoint,
    pub x_ij_points: Vec<C::ProjectivePoint>,

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, KeygenR1Broadcast>,

    // Outgoing
    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,

    // Received round 2 messages
    pub round2_broadcasts: BTreeMap<PartyId, KeygenR2Broadcast>,
    pub round2_p2p: BTreeMap<PartyId, KeygenR2P2p>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle_broadcast(
        &mut self,
        from: PartyId,
        msg: KeygenR2Broadcast,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.parties)?;
        if self.round2_broadcasts.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_broadcasts.insert(from, msg);
        Ok(())
    }

    pub fn handle_p2p(&mut self, from: PartyId, msg: KeygenR2P2p) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.parties)?;
        if self.round2_p2p.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_p2p.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_broadcasts.len() == self.expected_count()
            && self.round2_p2p.len() == self.expected_count()
    }

    /// Transition to Round 3: pass all collected data for final verification.
    pub fn advance(self) -> Round3State<C> {
        Round3State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            poly_coeffs: self.poly_coeffs,
            p_i_star: self.p_i_star,
            x_ij_points: self.x_ij_points,
            round1_commitments: self.round1_commitments,
            round2_broadcasts: self.round2_broadcasts,
            round2_p2p: self.round2_p2p,
            outgoing: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Round 3 state -- Verify + Compute (final)
// ---------------------------------------------------------------------------

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    // Configuration
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    // Own secrets
    pub poly_coeffs: Vec<C::Scalar>,
    pub p_i_star: C::ProjectivePoint,
    pub x_ij_points: Vec<C::ProjectivePoint>,

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, KeygenR1Broadcast>,

    // Round 2 data
    pub round2_broadcasts: BTreeMap<PartyId, KeygenR2Broadcast>,
    pub round2_p2p: BTreeMap<PartyId, KeygenR2P2p>,

    // Outgoing (always empty for round 3)
    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Verify all received data and compute the final key share.
    ///
    /// For each other party i:
    /// 1. Verify decommitment opens correctly (recompute hash and compare
    ///    against Round 1 commitment).
    /// 2. Verify s_{i,j} * G == X_{i,j} (share matches committed point).
    ///
    /// Then compute:
    /// - share_j = sum_i s_{i,j} (own combined Shamir share)
    /// - pk = sum_i P_i^* (joint public key)
    /// - V_j = sum_i X_{i,j} = share_j * G (verification shares)
    pub fn finish(mut self) -> tecdsa_core::Result<Dkls23KeyShare<C>> {
        let my_index = self.my_id.0; // 1-based

        // We need to collect P_i^* and X_{i,j} from all parties (including self).
        // Own share: s_{i,i} = p_i(my_index), computed from own polynomial.
        let own_share = evaluate_poly::<C>(&self.poly_coeffs, my_index);
        let mut combined_share = own_share;

        // Start computing pk with own P_i^*
        let mut public_key = self.p_i_star;

        // Start computing verification shares: V_j = sum_i X_{i,j}
        // Initialize from own X_{i,j} points.
        let mut verification_shares: Vec<C::ProjectivePoint> = self.x_ij_points.clone();

        // Process each other party
        for pid in &self.parties {
            if *pid == self.my_id {
                continue;
            }

            let r2_bc = self.round2_broadcasts.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 2 broadcast from party {pid}"))
            })?;

            let r1 = self.round1_commitments.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 1 commitment from party {pid}"))
            })?;

            // 1. Deserialize points from the broadcast
            if r2_bc.point_commitments.len() != self.total as usize {
                return Err(TecdsaError::InvalidShare(format!(
                    "party {pid} sent {} point commitments, expected {}",
                    r2_bc.point_commitments.len(),
                    self.total
                )));
            }

            let mut x_ij_from_sender: Vec<C::ProjectivePoint> =
                Vec::with_capacity(self.total as usize);
            for (k, bytes) in r2_bc.point_commitments.iter().enumerate() {
                let pt = C::ProjectivePoint::from_bytes_slice(bytes).ok_or_else(|| {
                    TecdsaError::Other(format!(
                        "party {pid} sent invalid X_{{i,{}}} point encoding",
                        k + 1
                    ))
                })?;
                x_ij_from_sender.push(pt);
            }

            let p_i_star_remote = C::ProjectivePoint::from_bytes_slice(&r2_bc.p_i_star)
                .ok_or_else(|| {
                    TecdsaError::Other(format!("party {pid} sent invalid P_i^* point encoding"))
                })?;

            // 2. Verify decommitment: recompute H(salt || X_{i,1} || ... || X_{i,n} || P_i^*)
            //    and compare against the round 1 commitment hash.
            //    (constant-time comparison to prevent timing side channels)
            let recomputed =
                compute_commitment::<C>(&r2_bc.salt, &x_ij_from_sender, &p_i_star_remote);
            if recomputed.ct_eq(&r1.commitment).unwrap_u8() == 0 {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} decommitment verification failed"
                )));
            }

            // 3. Verify s_{i,j} * G == X_{i,j} for my index j
            let r2_p2p = self.round2_p2p.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 2 P2P share from party {pid}"))
            })?;

            let s_ij = scalar_from_canonical_bytes::<C>(&r2_p2p.share).map_err(|_| {
                TecdsaError::Other(format!(
                    "party {pid} sent invalid scalar encoding for share"
                ))
            })?;

            let s_ij_G = C::generator() * s_ij;
            let expected_point = x_ij_from_sender[(my_index - 1) as usize];
            if s_ij_G != expected_point {
                return Err(TecdsaError::InvalidShare(format!(
                    "party {pid} share consistency check failed: \
                     s_{{i,j}} * G != X_{{i,j}}"
                )));
            }

            // 4. Accumulate combined share
            combined_share += s_ij;

            // 5. Accumulate public key
            public_key += p_i_star_remote;

            // 6. Accumulate verification shares
            for (k, x_ik) in x_ij_from_sender.iter().enumerate() {
                verification_shares[k] += *x_ik;
            }
        }

        let result = Ok(Dkls23KeyShare {
            party_index: my_index,
            shamir_share: combined_share,
            public_key,
            verification_shares,
            total: self.total,
            threshold: self.threshold,
            ot_seeds: BTreeMap::new(),
        });

        // Zeroize polynomial coefficients (secret polynomial)
        for s in &mut self.poly_coeffs {
            s.zeroize();
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Evaluate polynomial p(x) = sum_{k=0}^{t-1} a_k * x^k at x = j (1-based).
pub(crate) fn evaluate_poly<C: TecdsaCurve>(coeffs: &[C::Scalar], j: u16) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    // Convert j to a scalar. Build from the u64 representation.
    let j_scalar = scalar_from_u64::<C>(u64::from(j));

    // Horner's method: p(j) = a_0 + j*(a_1 + j*(a_2 + ...))
    let mut result = C::Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        result = result * j_scalar + *coeff;
    }
    result
}

/// Create a scalar from a u64 value.
fn scalar_from_u64<C: TecdsaCurve>(val: u64) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut repr = FieldBytes::<C>::default();
    let bytes = val.to_be_bytes();
    let repr_len = repr.len();
    // Place the 8 bytes of val at the end of the repr (big-endian).
    if repr_len >= 8 {
        repr[repr_len - 8..].copy_from_slice(&bytes);
    }
    // This unwrap is safe: small u64 values are always valid field elements.
    C::Scalar::from_repr(repr).expect("small u64 value must be a valid scalar")
}

/// Compute the commitment hash: H(salt || X_1 || ... || X_n || P_i^*).
fn compute_commitment<C: TecdsaCurve>(
    salt: &[u8; 32],
    points: &[C::ProjectivePoint],
    p_i_star: &C::ProjectivePoint,
) -> [u8; 32]
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut hasher = Sha256::new();
    hasher.update(salt);
    for pt in points {
        hasher.update(pt.to_bytes().as_ref());
    }
    hasher.update(p_i_star.to_bytes().as_ref());
    hasher.finalize().into()
}

// Point decoding uses `PointExt::from_bytes_slice`; `scalar_from_canonical_bytes`
// is imported from crate::utils.
