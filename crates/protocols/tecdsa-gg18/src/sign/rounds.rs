#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize,
    PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::zk::homo_elgamal::{
    HomoElGamalProof, HomoElGamalStatement, HomoElGamalWitness,
};
use tecdsa_protocol::{
    low_s_normalize, verify_ecdsa, DataToSign, Outgoing, PartyId, Recipient, Signature,
};
use zeroize::Zeroize;

use super::msg::*;
use crate::{presign::types::Gg18Presignature, sign::sign_keys::SignKeys};

#[derive(Default)]
pub(crate) enum OnlineSignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round4(Round4State<C>),
    Round5(Round5State<C>),
    Round6(Round6State<C>),
    Round7(Round7State<C>),
    Round8(Round8State<C>),
    Done(Signature<C>),
    #[default]
    Gone,
}

pub struct OnlineSignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub presignature: Gg18Presignature<C>,
    pub message: DataToSign<C>,
}

struct OnlineSharedState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    message: DataToSign<C>,
    public_key: C::ProjectivePoint,
}

pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: OnlineSharedState<C>,
    R: C::ProjectivePoint,
    r: C::Scalar,
    s_i: C::Scalar,
    l_i: C::Scalar,
    rho_i: C::Scalar,
    V_i: C::ProjectivePoint,
    A_i: C::ProjectivePoint,
    B_i: C::ProjectivePoint,
    decommit_nonce_5a: [u8; 32],
    homo_proof: HomoElGamalProof<C>,
    dlog_proof: DlogProof<C>,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round4_msgs: BTreeMap<PartyId, MsgPhase5aCommit>,
}

impl<C: TecdsaCurve> Round4State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: OnlineSignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let presig = config.presignature;
        let R = presig.R;
        let r = presig.r;

        let m = *config.message.digest();
        let s_i = SignKeys::<C>::compute_s_i_static(&m, &presig.k_i, &r, &presig.sigma_i);

        let l_i = C::random_scalar(rng);
        let rho_i = C::random_scalar(rng);

        let G = C::generator();
        let V_i = R * s_i + G * l_i;
        let A_i = G * rho_i;
        let l_i_rho_i = l_i * rho_i;
        let B_i = G * l_i_rho_i;

        let homo_stmt = HomoElGamalStatement::<C> {
            G: A_i,
            H: R,
            Y: G,
            D: V_i,
            E: B_i,
        };
        let homo_witness = HomoElGamalWitness::<C> { x: s_i, r: l_i };
        let homo_proof = HomoElGamalProof::prove(&homo_witness, &homo_stmt, rng);

        let schnorr_eph = C::random_scalar(rng);
        let dlog_proof = DlogProof::<C>::prove(&rho_i, &schnorr_eph, &A_i, &[]);

        let commit_data_5a = build_phase5_commit_data::<C>(&V_i, &A_i, &B_i);
        let (commitment_5a, decommit_nonce_5a) = HashCommitment::commit(&commit_data_5a, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round4(MsgPhase5aCommit {
                commitment: commitment_5a,
            }),
        }];

        Self {
            shared: OnlineSharedState {
                my_id: presig.my_id,
                signer_parties: presig.signer_parties,
                message: config.message,
                public_key: presig.public_key,
            },
            R,
            r,
            s_i,
            l_i,
            rho_i,
            V_i,
            A_i,
            B_i,
            decommit_nonce_5a,
            homo_proof,
            dlog_proof,
            outgoing,
            round4_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgPhase5aCommit) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round4_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round4_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round4_msgs.len() == self.expected_count()
    }

    pub fn advance(self) -> Round5State<C> {
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round5(MsgPhase5bDecommit {
                V_i: self.V_i,
                A_i: self.A_i,
                B_i: self.B_i,
                decommit_nonce: self.decommit_nonce_5a,
                homo_proof: self.homo_proof.clone(),
                dlog_proof: self.dlog_proof.clone(),
            }),
        }];

        Round5State {
            shared: self.shared,
            R: self.R,
            r: self.r,
            s_i: self.s_i,
            l_i: self.l_i,
            rho_i: self.rho_i,
            V_i: self.V_i,
            A_i: self.A_i,
            B_i: self.B_i,
            round4_msgs: self.round4_msgs,
            outgoing,
            round5_msgs: BTreeMap::new(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct Round5State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: OnlineSharedState<C>,
    R: C::ProjectivePoint,
    r: C::Scalar,
    s_i: C::Scalar,
    l_i: C::Scalar,
    rho_i: C::Scalar,
    V_i: C::ProjectivePoint,
    A_i: C::ProjectivePoint,
    B_i: C::ProjectivePoint,
    round4_msgs: BTreeMap<PartyId, MsgPhase5aCommit>,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round5_msgs: BTreeMap<PartyId, MsgPhase5bDecommit<C>>,
}

impl<C: TecdsaCurve> Round5State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgPhase5bDecommit<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round5_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round5_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round5_msgs.len() == self.expected_count()
    }

    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<Round6State<C>> {
        let G = C::generator();

        for (&pid, decom) in &self.round5_msgs {
            let commit = self
                .round4_msgs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round4 from {pid}")))?;

            let commit_data = build_phase5_commit_data::<C>(&decom.V_i, &decom.A_i, &decom.B_i);
            if !commit
                .commitment
                .verify(&commit_data, &decom.decommit_nonce)
            {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} Phase 5a decommitment failed"
                )));
            }

            let homo_stmt = HomoElGamalStatement::<C> {
                G: decom.A_i,
                H: self.R,
                Y: G,
                D: decom.V_i,
                E: decom.B_i,
            };
            decom.homo_proof.verify(&homo_stmt).map_err(|_| {
                TecdsaError::InvalidProof(format!(
                    "party {pid} HomoElGamal proof verification failed"
                ))
            })?;

            if !decom.dlog_proof.verify(&decom.A_i, &[]) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} DLog proof for rho_i failed"
                )));
            }
        }

        let mut V = self.V_i;
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            V += self.round5_msgs[&pid].V_i;
        }

        let mut A_sum = self.A_i;
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            A_sum += self.round5_msgs[&pid].A_i;
        }

        let m = *self.shared.message.digest();
        let gm = G * m;
        let yr = self.shared.public_key * self.r;
        let V_check = V - gm - yr;

        let U_i = V_check * self.rho_i;
        let T_i = A_sum * self.l_i;

        let commit_data_5c = build_phase5c_commit_data::<C>(&U_i, &T_i);
        let (commitment_5c, decommit_nonce_5c) = HashCommitment::commit(&commit_data_5c, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round6(MsgPhase5cCommit {
                commitment: commitment_5c,
            }),
        }];

        self.l_i.zeroize();
        self.rho_i.zeroize();

        Ok(Round6State {
            shared: self.shared,
            R: self.R,
            r: self.r,
            s_i: self.s_i,
            U_i,
            T_i,
            decommit_nonce_5c,
            outgoing,
            round6_msgs: BTreeMap::new(),
        })
    }
}

pub(crate) struct Round6State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: OnlineSharedState<C>,
    R: C::ProjectivePoint,
    r: C::Scalar,
    s_i: C::Scalar,
    U_i: C::ProjectivePoint,
    T_i: C::ProjectivePoint,
    decommit_nonce_5c: [u8; 32],
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round6_msgs: BTreeMap<PartyId, MsgPhase5cCommit>,
}

impl<C: TecdsaCurve> Round6State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgPhase5cCommit) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round6_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round6_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round6_msgs.len() == self.expected_count()
    }

    pub fn advance(self) -> Round7State<C> {
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round7(MsgPhase5dDecommit {
                U_i: self.U_i,
                T_i: self.T_i,
                decommit_nonce: self.decommit_nonce_5c,
            }),
        }];

        Round7State {
            shared: self.shared,
            R: self.R,
            r: self.r,
            s_i: self.s_i,
            U_i: self.U_i,
            T_i: self.T_i,
            round6_msgs: self.round6_msgs,
            outgoing,
            round7_msgs: BTreeMap::new(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct Round7State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: OnlineSharedState<C>,
    R: C::ProjectivePoint,
    r: C::Scalar,
    s_i: C::Scalar,
    U_i: C::ProjectivePoint,
    T_i: C::ProjectivePoint,
    round6_msgs: BTreeMap<PartyId, MsgPhase5cCommit>,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round7_msgs: BTreeMap<PartyId, MsgPhase5dDecommit<C>>,
}

impl<C: TecdsaCurve> Round7State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgPhase5dDecommit<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round7_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round7_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round7_msgs.len() == self.expected_count()
    }

    pub fn advance(self) -> tecdsa_core::Result<Round8State<C>> {
        for (&pid, decom) in &self.round7_msgs {
            let commit = self
                .round6_msgs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round6 from {pid}")))?;

            let commit_data = build_phase5c_commit_data::<C>(&decom.U_i, &decom.T_i);
            if !commit
                .commitment
                .verify(&commit_data, &decom.decommit_nonce)
            {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} Phase 5d decommitment failed"
                )));
            }
        }

        let mut sum_T = self.T_i;
        let mut sum_U = self.U_i;
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            sum_T += self.round7_msgs[&pid].T_i;
            sum_U += self.round7_msgs[&pid].U_i;
        }

        if sum_T.to_bytes().as_ref() != sum_U.to_bytes().as_ref() {
            return Err(TecdsaError::InvalidProof(
                "Phase 5 zero-check failed: sum(T_i) != sum(U_i)".into(),
            ));
        }

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round8(MsgPhase5eSig { s_i: self.s_i }),
        }];

        Ok(Round8State {
            shared: self.shared,
            r: self.r,
            s_i: self.s_i,
            outgoing,
            round8_msgs: BTreeMap::new(),
        })
    }
}

pub(crate) struct Round8State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: OnlineSharedState<C>,
    r: C::Scalar,
    s_i: C::Scalar,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round8_msgs: BTreeMap<PartyId, MsgPhase5eSig<C>>,
}

impl<C: TecdsaCurve> Round8State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgPhase5eSig<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round8_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round8_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round8_msgs.len() == self.expected_count()
    }

    pub fn finish(mut self) -> tecdsa_core::Result<Signature<C>> {
        let mut s: C::Scalar = self.s_i;
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            s += self.round8_msgs[&pid].s_i;
        }

        let s = low_s_normalize::<C>(s);

        let sig = Signature { r: self.r, s };

        verify_ecdsa::<C>(&sig, &self.shared.public_key, &self.shared.message)?;

        self.s_i.zeroize();

        Ok(sig)
    }
}

fn build_phase5_commit_data<C: TecdsaCurve>(
    V: &C::ProjectivePoint,
    A: &C::ProjectivePoint,
    B: &C::ProjectivePoint,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut data = Vec::new();
    data.extend_from_slice(V.to_bytes().as_ref());
    data.extend_from_slice(A.to_bytes().as_ref());
    data.extend_from_slice(B.to_bytes().as_ref());
    data
}

fn build_phase5c_commit_data<C: TecdsaCurve>(
    U: &C::ProjectivePoint,
    T: &C::ProjectivePoint,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    let mut data = Vec::new();
    data.extend_from_slice(U.to_bytes().as_ref());
    data.extend_from_slice(T.to_bytes().as_ref());
    data
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
