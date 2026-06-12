#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use super::msg::{Dkls23KeygenMsg, KeygenR1Broadcast, KeygenR2Broadcast, KeygenR2P2p};
use crate::{
    key_share::Dkls23KeyShare,
    utils::{deserialize_point, deserialize_scalar, validate_sender},
};

pub(crate) struct KeygenConfig {
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
}

#[derive(Default)]
#[allow(dead_code)]
pub(crate) enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Dkls23KeyShare<C>),
    #[default]
    Poisoned,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    pub poly_coeffs: Vec<C::Scalar>,
    pub p_i_star: C::ProjectivePoint,
    pub x_ij_points: Vec<C::ProjectivePoint>,
    pub salt: [u8; 32],

    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,

    pub round1_msgs: BTreeMap<PartyId, KeygenR1Broadcast>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: KeygenConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.my_id;
        let parties = config.all_parties;
        let threshold = config.threshold;
        let total = config.total;

        let mut poly_coeffs = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            poly_coeffs.push(C::random_scalar(rng));
        }

        let p_i_star = C::generator() * poly_coeffs[0];

        let mut x_ij_points = Vec::with_capacity(total as usize);
        for j in 1..=total {
            let p_i_j = evaluate_poly::<C>(&poly_coeffs, j);
            let x_ij = C::generator() * p_i_j;
            x_ij_points.push(x_ij);
        }

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let commitment = compute_commitment::<C>(&salt, &x_ij_points, &p_i_star);

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

    pub fn advance(self) -> Round2State<C> {
        let point_commitments: Vec<Vec<u8>> = self
            .x_ij_points
            .iter()
            .map(|pt| pt.to_bytes().as_ref().to_vec())
            .collect();
        let p_i_star_bytes = self.p_i_star.to_bytes().as_ref().to_vec();

        let mut outgoing = Vec::new();

        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23KeygenMsg::Round2Broadcast(KeygenR2Broadcast {
                salt: self.salt,
                point_commitments,
                p_i_star: p_i_star_bytes,
            }),
        });

        for pid in &self.parties {
            if *pid == self.my_id {
                continue;
            }
            let j = pid.0;
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

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    pub poly_coeffs: Vec<C::Scalar>,
    pub p_i_star: C::ProjectivePoint,
    pub x_ij_points: Vec<C::ProjectivePoint>,

    pub round1_commitments: BTreeMap<PartyId, KeygenR1Broadcast>,

    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,

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

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    pub poly_coeffs: Vec<C::Scalar>,
    pub p_i_star: C::ProjectivePoint,
    pub x_ij_points: Vec<C::ProjectivePoint>,

    pub round1_commitments: BTreeMap<PartyId, KeygenR1Broadcast>,

    pub round2_broadcasts: BTreeMap<PartyId, KeygenR2Broadcast>,
    pub round2_p2p: BTreeMap<PartyId, KeygenR2P2p>,

    pub outgoing: Vec<Outgoing<Dkls23KeygenMsg>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn finish(mut self) -> tecdsa_core::Result<Dkls23KeyShare<C>> {
        let my_index = self.my_id.0;

        let own_share = evaluate_poly::<C>(&self.poly_coeffs, my_index);
        let mut combined_share = own_share;

        let mut public_key = self.p_i_star;

        let mut verification_shares: Vec<C::ProjectivePoint> = self.x_ij_points.clone();

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
                let pt = deserialize_point::<C>(bytes).map_err(|_| {
                    TecdsaError::Other(format!(
                        "party {pid} sent invalid X_{{i,{}}} point encoding",
                        k + 1
                    ))
                })?;
                x_ij_from_sender.push(pt);
            }

            let p_i_star_remote = deserialize_point::<C>(&r2_bc.p_i_star).map_err(|_| {
                TecdsaError::Other(format!("party {pid} sent invalid P_i^* point encoding"))
            })?;

            let recomputed =
                compute_commitment::<C>(&r2_bc.salt, &x_ij_from_sender, &p_i_star_remote);
            if recomputed.ct_eq(&r1.commitment).unwrap_u8() == 0 {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} decommitment verification failed"
                )));
            }

            let r2_p2p = self.round2_p2p.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 2 P2P share from party {pid}"))
            })?;

            let s_ij = deserialize_scalar::<C>(&r2_p2p.share).map_err(|_| {
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

            combined_share += s_ij;

            public_key += p_i_star_remote;

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

        for s in &mut self.poly_coeffs {
            s.zeroize();
        }

        result
    }
}

pub(crate) fn evaluate_poly<C: TecdsaCurve>(coeffs: &[C::Scalar], j: u16) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let j_scalar = scalar_from_u64::<C>(u64::from(j));

    let mut result = C::Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        result = result * j_scalar + *coeff;
    }
    result
}

fn scalar_from_u64<C: TecdsaCurve>(val: u64) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut repr = FieldBytes::<C>::default();
    let bytes = val.to_be_bytes();
    let repr_len = repr.len();
    if repr_len >= 8 {
        repr[repr_len - 8..].copy_from_slice(&bytes);
    }
    C::Scalar::from_repr(repr).expect("small u64 value must be a valid scalar")
}

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
