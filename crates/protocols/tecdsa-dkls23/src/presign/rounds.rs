#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, GroupEncoding},
    ops::Reduce,
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::{
    rvole::{MulDataToKeep, MulReceiver, MulSender},
    seed_state::OtSeedState,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use tecdsa_vss::lagrange;
use zeroize::Zeroize;

use super::types::{Dkls23Presignature, PartyRvoleData};
use crate::{
    key_share::Dkls23KeyShare,
    sign::msg::{Dkls23SignMsg, SignR1Broadcast, SignR1P2p, SignR2Broadcast, SignR2P2p, SignR3P2p},
    utils::{deserialize_point, deserialize_scalar, scalar_to_bytes, validate_sender},
};

pub struct PresignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Dkls23KeyShare<C>,
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
}

#[derive(Default)]
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Dkls23Presignature<C>),
    #[default]
    Poisoned,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub key_share: Dkls23KeyShare<C>,

    pub sk_i: C::Scalar,
    pub pk_i: C::ProjectivePoint,
    pub r_i: C::Scalar,
    pub R_i: C::ProjectivePoint,
    pub phi_i: C::Scalar,
    pub salt: [u8; 32],

    pub mul_senders: BTreeMap<u16, MulSender>,

    pub outgoing: Vec<Outgoing<Dkls23SignMsg<C>>>,
    pub round1_broadcasts: BTreeMap<PartyId, SignR1Broadcast>,
    pub round1_p2ps: BTreeMap<PartyId, SignR1P2p>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>> + Reduce<FieldBytes<C>>,
{
    pub fn new(config: PresignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.my_id;
        let signer_parties = config.signer_parties;
        let key_share = config.key_share;

        let signer_indices: Vec<u16> = signer_parties.iter().map(|p| p.0).collect();
        let lagrange_coeffs = lagrange::coefficients::<C>(&signer_indices);
        let my_pos = signer_indices
            .iter()
            .position(|&idx| idx == my_id.0)
            .expect("this party must be in the signing subset");
        let lambda_i = lagrange_coeffs[my_pos];

        let sk_i = lambda_i * key_share.shamir_share;
        let pk_i = C::generator() * sk_i;

        let r_i = C::random_scalar(rng);
        let R_i = C::generator() * r_i;

        let phi_i = C::random_scalar(rng);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let commitment = compute_nonce_commitment::<C>(&salt, &R_i);

        let mut outgoing = Vec::new();

        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23SignMsg::Round1Broadcast(SignR1Broadcast { commitment }),
        });

        let mut mul_senders = BTreeMap::new();

        for &pid in &signer_parties {
            if pid == my_id {
                continue;
            }

            let session_id = rvole_session_id(my_id.0, pid.0);

            let nonce = C::random_scalar(rng);
            let nonce_bytes = scalar_to_bytes::<C>(&nonce);

            let (mul_sender, ote_init_msg) = MulSender::init::<C>(&session_id, &nonce, rng);

            mul_senders.insert(pid.0, mul_sender);

            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Dkls23SignMsg::Round1P2p(SignR1P2p {
                    ote_init_msg,
                    nonce: nonce_bytes,
                }),
            });
        }

        Self {
            my_id,
            signer_parties,
            key_share,
            sk_i,
            pk_i,
            r_i,
            R_i,
            phi_i,
            salt,
            mul_senders,
            outgoing,
            round1_broadcasts: BTreeMap::new(),
            round1_p2ps: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.signer_parties.len() - 1
    }

    pub fn handle_broadcast(
        &mut self,
        from: PartyId,
        msg: SignR1Broadcast,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round1_broadcasts.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_broadcasts.insert(from, msg);
        Ok(())
    }

    pub fn handle_p2p(&mut self, from: PartyId, msg: SignR1P2p) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round1_p2ps.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_p2ps.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round1_broadcasts.len() == self.expected_count()
            && self.round1_p2ps.len() == self.expected_count()
    }

    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<Round2State<C>> {
        let R_i_bytes = self.R_i.to_bytes().as_ref().to_vec();

        let mut outgoing = Vec::new();

        outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Dkls23SignMsg::Round2Broadcast(SignR2Broadcast {
                salt: self.salt,
                R_i: R_i_bytes,
            }),
        });

        let mut mul_receivers = BTreeMap::new();
        let mut chi_values = BTreeMap::new();
        let mut data_to_keep_map = BTreeMap::new();

        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }

            let r1_p2p = self.round1_p2ps.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 1 P2P from party {pid}"))
            })?;

            let session_id = rvole_session_id(pid.0, self.my_id.0);

            let nonce = deserialize_scalar::<C>(&r1_p2p.nonce)
                .map_err(|_| TecdsaError::Other(format!("party {pid} sent invalid RVOLE nonce")))?;

            let mul_receiver = MulReceiver::init::<C>(&session_id, &nonce, &r1_p2p.ote_init_msg)
                .map_err(|e| {
                    TecdsaError::Other(format!("MulReceiver init failed for party {pid}: {e}"))
                })?;

            let (chi, data_to_keep, ote_data_to_sender) = mul_receiver
                .run_phase1::<C>(&session_id, rng)
                .map_err(|e| {
                    TecdsaError::Other(format!("MulReceiver phase1 failed for party {pid}: {e}"))
                })?;

            chi_values.insert(pid.0, chi);
            data_to_keep_map.insert(pid.0, data_to_keep);
            mul_receivers.insert(pid.0, mul_receiver);

            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Dkls23SignMsg::Round2P2p(SignR2P2p {
                    ote_data: ote_data_to_sender,
                }),
            });
        }

        Ok(Round2State {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            key_share: self.key_share,
            sk_i: self.sk_i,
            pk_i: self.pk_i,
            r_i: self.r_i,
            R_i: self.R_i,
            phi_i: self.phi_i,
            mul_senders: self.mul_senders,
            mul_receivers,
            chi_values,
            data_to_keep_map,
            round1_commitments: self.round1_broadcasts,
            outgoing,
            round2_broadcasts: BTreeMap::new(),
            round2_p2ps: BTreeMap::new(),
        })
    }
}

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub key_share: Dkls23KeyShare<C>,

    pub sk_i: C::Scalar,
    pub pk_i: C::ProjectivePoint,
    pub r_i: C::Scalar,
    pub R_i: C::ProjectivePoint,
    pub phi_i: C::Scalar,

    pub mul_senders: BTreeMap<u16, MulSender>,

    pub mul_receivers: BTreeMap<u16, MulReceiver>,
    pub chi_values: BTreeMap<u16, C::Scalar>,
    pub data_to_keep_map: BTreeMap<u16, MulDataToKeep>,

    pub round1_commitments: BTreeMap<PartyId, SignR1Broadcast>,

    pub outgoing: Vec<Outgoing<Dkls23SignMsg<C>>>,

    pub round2_broadcasts: BTreeMap<PartyId, SignR2Broadcast>,
    pub round2_p2ps: BTreeMap<PartyId, SignR2P2p>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>> + Reduce<FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.signer_parties.len() - 1
    }

    pub fn handle_broadcast(
        &mut self,
        from: PartyId,
        msg: SignR2Broadcast,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round2_broadcasts.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_broadcasts.insert(from, msg);
        Ok(())
    }

    pub fn handle_p2p(&mut self, from: PartyId, msg: SignR2P2p) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round2_p2ps.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_p2ps.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_broadcasts.len() == self.expected_count()
            && self.round2_p2ps.len() == self.expected_count()
    }

    pub fn advance(self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<Round3State<C>> {
        let mut outgoing = Vec::new();

        let mut sender_outputs: BTreeMap<u16, (C::Scalar, C::Scalar)> = BTreeMap::new();

        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }

            let r2_p2p = self.round2_p2ps.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 2 P2P from party {pid}"))
            })?;

            let session_id = rvole_session_id(self.my_id.0, pid.0);

            let mul_sender = self
                .mul_senders
                .get(&pid.0)
                .ok_or_else(|| TecdsaError::Other(format!("missing MulSender for party {pid}")))?;

            let input = [self.r_i, self.sk_i];

            let (output, mul_data_to_receiver) = mul_sender
                .run::<C>(&session_id, &input, &r2_p2p.ote_data, rng)
                .map_err(|e| {
                    TecdsaError::Other(format!("MulSender run failed for party {pid}: {e}"))
                })?;

            let c_u = output[0];
            let c_v = output[1];
            sender_outputs.insert(pid.0, (c_u, c_v));

            let Gamma_u = C::generator() * c_u;
            let Gamma_v = C::generator() * c_v;

            let chi = self
                .chi_values
                .get(&pid.0)
                .ok_or_else(|| TecdsaError::Other(format!("missing chi value for party {pid}")))?;
            let psi = self.phi_i - *chi;

            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Dkls23SignMsg::Round3P2p(SignR3P2p {
                    mul_data: mul_data_to_receiver,
                    Gamma_u,
                    Gamma_v,
                    psi,
                    pk_i: self.pk_i,
                }),
            });
        }

        Ok(Round3State {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            key_share: self.key_share,
            sk_i: self.sk_i,
            pk_i: self.pk_i,
            r_i: self.r_i,
            R_i: self.R_i,
            phi_i: self.phi_i,
            mul_senders: self.mul_senders,
            mul_receivers: self.mul_receivers,
            chi_values: self.chi_values,
            data_to_keep_map: self.data_to_keep_map,
            sender_outputs,
            round1_commitments: self.round1_commitments,
            round2_broadcasts: self.round2_broadcasts,
            outgoing,
            round3_p2ps: BTreeMap::new(),
        })
    }
}

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
    pub key_share: Dkls23KeyShare<C>,

    pub sk_i: C::Scalar,
    pub pk_i: C::ProjectivePoint,
    pub r_i: C::Scalar,
    pub R_i: C::ProjectivePoint,
    pub phi_i: C::Scalar,

    pub mul_senders: BTreeMap<u16, MulSender>,

    pub mul_receivers: BTreeMap<u16, MulReceiver>,
    pub chi_values: BTreeMap<u16, C::Scalar>,
    pub data_to_keep_map: BTreeMap<u16, MulDataToKeep>,

    pub sender_outputs: BTreeMap<u16, (C::Scalar, C::Scalar)>,

    pub round1_commitments: BTreeMap<PartyId, SignR1Broadcast>,
    pub round2_broadcasts: BTreeMap<PartyId, SignR2Broadcast>,

    pub outgoing: Vec<Outgoing<Dkls23SignMsg<C>>>,

    pub round3_p2ps: BTreeMap<PartyId, SignR3P2p<C>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>> + Reduce<FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.signer_parties.len() - 1
    }

    pub fn handle_p2p(&mut self, from: PartyId, msg: SignR3P2p<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.my_id, &self.signer_parties)?;
        if self.round3_p2ps.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round3_p2ps.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round3_p2ps.len() == self.expected_count()
    }

    pub fn finish(mut self) -> tecdsa_core::Result<Dkls23Presignature<C>> {
        let mut R = self.R_i;

        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }

            let r2_bc = self.round2_broadcasts.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 2 broadcast from party {pid}"))
            })?;

            let r1 = self.round1_commitments.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 1 commitment from party {pid}"))
            })?;

            let R_j = deserialize_point::<C>(&r2_bc.R_i).map_err(|_| {
                TecdsaError::Other(format!("party {pid} sent invalid R_i point encoding"))
            })?;

            let recomputed = compute_nonce_commitment::<C>(&r2_bc.salt, &R_j);
            if recomputed.ct_eq(&r1.commitment).unwrap_u8() == 0 {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} nonce decommitment verification failed"
                )));
            }

            R += R_j;
        }

        let mut pk_sum = self.pk_i;
        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }
            let r3_p2p = &self.round3_p2ps[&pid];
            pk_sum += r3_p2p.pk_i;
        }
        if pk_sum.to_bytes().as_ref() != self.key_share.public_key.to_bytes().as_ref() {
            return Err(TecdsaError::InvalidProof(
                "sum of Lagrange-weighted public keys does not match global public key".into(),
            ));
        }

        let mut rvole_data = BTreeMap::new();

        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }

            let r3_p2p = self.round3_p2ps.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round 3 P2P from party {pid}"))
            })?;

            let session_id = rvole_session_id(pid.0, self.my_id.0);
            let mul_receiver = self.mul_receivers.get(&pid.0).ok_or_else(|| {
                TecdsaError::Other(format!("missing MulReceiver for party {pid}"))
            })?;
            let data_to_keep = self.data_to_keep_map.get(&pid.0).ok_or_else(|| {
                TecdsaError::Other(format!("missing MulDataToKeep for party {pid}"))
            })?;

            let receiver_output = mul_receiver
                .run_phase2::<C>(&session_id, data_to_keep, &r3_p2p.mul_data)
                .map_err(|e| {
                    TecdsaError::Other(format!("MulReceiver phase2 failed for party {pid}: {e}"))
                })?;

            let d_u = receiver_output[0];
            let d_v = receiver_output[1];

            let chi = self.chi_values[&pid.0];

            let r2_bc = self
                .round2_broadcasts
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 broadcast from {pid}")))?;
            let R_j = deserialize_point::<C>(&r2_bc.R_i)
                .map_err(|_| TecdsaError::Other(format!("invalid R_j from {pid}")))?;

            let gamma_u = r3_p2p.Gamma_u;
            let gamma_v = r3_p2p.Gamma_v;
            let pk_j = r3_p2p.pk_i;

            let lhs_u = R_j * chi - gamma_u;
            let rhs_u = C::generator() * d_u;
            if lhs_u.to_bytes().as_ref() != rhs_u.to_bytes().as_ref() {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} RVOLE nonce consistency check failed (Gamma^u)"
                )));
            }

            let lhs_v = pk_j * chi - gamma_v;
            let rhs_v = C::generator() * d_v;
            if lhs_v.to_bytes().as_ref() != rhs_v.to_bytes().as_ref() {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} RVOLE key consistency check failed (Gamma^v)"
                )));
            }

            let (c_u, c_v) = self.sender_outputs[&pid.0];

            rvole_data.insert(
                pid.0,
                PartyRvoleData {
                    chi,
                    c_u,
                    c_v,
                    d_u,
                    d_v,
                },
            );
        }

        let R_affine = R.to_affine();
        let r_x = C::xcoord_mod_q(&R_affine);

        let mut received_psi = BTreeMap::new();
        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }
            let r3_p2p = &self.round3_p2ps[&pid];
            received_psi.insert(pid.0, r3_p2p.psi);
        }

        let mut key_share = self.key_share;
        for &pid in &self.signer_parties {
            if pid == self.my_id {
                continue;
            }

            let mul_sender = self.mul_senders.get(&pid.0).ok_or_else(|| {
                TecdsaError::Other(format!(
                    "missing MulSender for party {pid} during seed extraction"
                ))
            })?;
            let sender_corr = mul_sender.ote_sender.correlation.clone();
            let sender_seeds = mul_sender.ote_sender.seeds.clone();

            let mul_receiver = self.mul_receivers.get(&pid.0).ok_or_else(|| {
                TecdsaError::Other(format!(
                    "missing MulReceiver for party {pid} during seed extraction"
                ))
            })?;
            let recv_seeds0 = mul_receiver.ote_receiver.seeds0.clone();
            let recv_seeds1 = mul_receiver.ote_receiver.seeds1.clone();

            let seed_state = OtSeedState::new(sender_corr, sender_seeds, recv_seeds0, recv_seeds1);
            key_share.ot_seeds.insert(pid.0, seed_state);
        }

        for v in self.chi_values.values_mut() {
            v.zeroize();
        }

        Ok(Dkls23Presignature {
            my_id: self.my_id,
            signer_parties: self.signer_parties,
            r_i: self.r_i,
            phi_i: self.phi_i,
            sk_i: self.sk_i,
            pk_i: self.pk_i,
            R,
            r_x,
            rvole_data,
            received_psi,
            key_share,
        })
    }
}

fn compute_nonce_commitment<C: TecdsaCurve>(salt: &[u8; 32], R_i: &C::ProjectivePoint) -> [u8; 32]
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(R_i.to_bytes().as_ref());
    hasher.finalize().into()
}

fn rvole_session_id(sender_idx: u16, receiver_idx: u16) -> Vec<u8> {
    let mut sid = Vec::with_capacity(32);
    sid.extend_from_slice(b"dkls23-rvole/");
    sid.extend_from_slice(&sender_idx.to_be_bytes());
    sid.push(b'/');
    sid.extend_from_slice(&receiver_idx.to_be_bytes());
    sid
}
