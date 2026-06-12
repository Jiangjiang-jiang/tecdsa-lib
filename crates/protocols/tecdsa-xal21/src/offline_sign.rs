use elliptic_curve::{
    group::Curve as CurveGroup, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_protocol::MtA;

use crate::{
    error::Xal21Error,
    key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare},
    keygen::{curve_order, int_to_scalar},
};

pub type DefaultMtA = tecdsa_paillier::mta::PaillierMtA<tecdsa_paillier::mta::Gg18Proofs>;

pub struct Party1Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k1: C::Scalar,
    pub x1_prime: C::Scalar,
    pub r: C::Scalar,
    pub R: C::ProjectivePoint,
}

pub struct Party2Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k2: C::Scalar,
    pub r1: C::Scalar,
    pub x2_prime: C::Scalar,
    pub r: C::Scalar,
}

impl<C: TecdsaCurve> zeroize::Zeroize for Party1Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k1.zeroize();
        self.x1_prime.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for Party1Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl<C: TecdsaCurve> zeroize::Zeroize for Party2Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k2.zeroize();
        self.x2_prime.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for Party2Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step1Commitment {
    pub f2: HashCommitment,
}

pub struct Step1P2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub k2: C::Scalar,
    pub R2: C::ProjectivePoint,
    pub nizk3: DlogProof<C>,
    pub commit_nonce: [u8; 32],
}

pub fn step1_p2_commit<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Step1Commitment, Step1P2State<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2 = C::random_scalar(rng);
    let R2 = C::generator() * k2;

    let ephemeral = C::random_scalar(rng);
    let nizk3 = DlogProof::<C>::prove(&k2, &ephemeral, &R2, b"xal21-sign-R2");

    let commit_data = serialize_point_and_proof::<C>(&R2, &nizk3);
    let (f2, commit_nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = Step1Commitment { f2 };
    let state = Step1P2State {
        k2,
        R2,
        nizk3,
        commit_nonce,
    };

    (msg, state)
}

pub struct Step2P1ToP2Msg<C: TecdsaCurve, M: MtA>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub Q1_prime: C::ProjectivePoint,
    pub r1: C::Scalar,
    pub cc: C::Scalar,
    pub mta_msg: M::ReceiverMsg,
}

pub struct Step2P1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub x1_prime: C::Scalar,
    pub r1: C::Scalar,
}

pub fn step2_p2_encrypt_k2<C: TecdsaCurve, M: MtA>(
    setup: &M::Setup,
    k2: &C::Scalar,
    rng: &mut impl CryptoRngCore,
) -> Result<(M::SenderMsg, M::SenderState), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2_bytes = crate::keygen::scalar_to_bytes::<C>(k2);
    let q_bytes = q_bytes::<C>();

    M::sender_encrypt(setup, &k2_bytes, &q_bytes, rng)
        .map_err(|e| Xal21Error::Paillier(format!("MtA sender_encrypt failed: {e}")))
}

pub fn step2_p1_compute<C: TecdsaCurve, M: MtA>(
    key_share: &Xal21Party1KeyShare<C>,
    setup: &M::Setup,
    sender_msg: &M::SenderMsg,
    rng: &mut impl CryptoRngCore,
) -> Result<(Step2P1ToP2Msg<C, M>, Step2P1State<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1_prime = C::random_scalar(rng);
    let Q1_prime = C::generator() * x1_prime;

    let x1p_bytes = crate::keygen::scalar_to_bytes::<C>(&x1_prime);
    let q_bytes = q_bytes::<C>();

    let (receiver_msg, alpha_bytes) =
        M::receiver_compute(setup, &x1p_bytes, &q_bytes, sender_msg, rng).map_err(|e| {
            Xal21Error::MtaProofVerification(format!("MtA receiver_compute failed: {e}"))
        })?;

    let alpha_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&alpha_bytes);
    let t_A = int_to_scalar::<C>(&alpha_int);

    let r1 = C::random_scalar(rng);
    let cc = t_A + x1_prime * r1 - key_share.secret_share;

    let msg = Step2P1ToP2Msg {
        Q1_prime,
        r1,
        cc,
        mta_msg: receiver_msg,
    };

    let state = Step2P1State { x1_prime, r1 };

    Ok((msg, state))
}

pub fn step2_p2_verify<C: TecdsaCurve, M: MtA>(
    key_share: &Xal21Party2KeyShare<C>,
    setup: &M::Setup,
    sender_state: &M::SenderState,
    k2: &C::Scalar,
    p1_msg: &Step2P1ToP2Msg<C, M>,
) -> Result<C::Scalar, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_bytes = q_bytes::<C>();

    let beta_bytes = M::sender_decrypt(setup, sender_state, &q_bytes, &p1_msg.mta_msg)
        .map_err(|e| Xal21Error::Paillier(format!("MtA sender_decrypt failed: {e}")))?;

    let beta_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&beta_bytes);
    let t_B = int_to_scalar::<C>(&beta_int);

    let tb_plus_cc = t_B + p1_msg.cc;
    let lhs = C::generator() * tb_plus_cc;

    let r1_plus_k2 = p1_msg.r1 + *k2;
    let rhs = p1_msg.Q1_prime * r1_plus_k2 - key_share.public_share_p1;

    if lhs != rhs {
        return Err(Xal21Error::ConsistencyCheck(
            "re-sharing consistency check failed: (t_B + cc)*G != (r_1 + k_2)*Q'_1 - Q_1".into(),
        ));
    }

    let x2_prime = key_share.secret_share - tb_plus_cc;

    Ok(x2_prime)
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step3P1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub R1: C::ProjectivePoint,
    pub nizk4: DlogProof<C>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Step3P2Decommit<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub R2: C::ProjectivePoint,
    pub nizk3: DlogProof<C>,
    pub commit_nonce: [u8; 32],
}

pub fn step3_p1_send_nonce<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Step3P1Msg<C>, C::Scalar)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k1 = C::random_scalar(rng);
    let R1 = C::generator() * k1;

    let ephemeral = C::random_scalar(rng);
    let nizk4 = DlogProof::<C>::prove(&k1, &ephemeral, &R1, b"xal21-sign-R1");

    let msg = Step3P1Msg { R1, nizk4 };
    (msg, k1)
}

pub fn step3_p2_decommit_and_compute_R<C: TecdsaCurve>(
    state: &Step1P2State<C>,
    p1_msg: &Step3P1Msg<C>,
    r1: &C::Scalar,
    x2_prime: C::Scalar,
) -> Result<(Step3P2Decommit<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !p1_msg.nizk4.verify(&p1_msg.R1, b"xal21-sign-R1") {
        return Err(Xal21Error::DlogVerification(
            "P_1 nonce DLog proof (nizk4) failed".into(),
        ));
    }

    let r1_plus_k2 = *r1 + state.k2;
    let R = p1_msg.R1 * r1_plus_k2;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    let decommit = Step3P2Decommit {
        R2: state.R2,
        nizk3: state.nizk3.clone(),
        commit_nonce: state.commit_nonce,
    };

    let presig = Party2Presignature {
        k2: state.k2,
        r1: *r1,
        x2_prime,
        r,
    };

    Ok((decommit, presig))
}

pub fn step3_p1_verify_and_compute_R<C: TecdsaCurve>(
    f2: &Step1Commitment,
    p2_decommit: &Step3P2Decommit<C>,
    k1: C::Scalar,
    step2_state: &Step2P1State<C>,
) -> Result<Party1Presignature<C>, Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let commit_data = serialize_point_and_proof::<C>(&p2_decommit.R2, &p2_decommit.nizk3);
    if !f2.f2.verify(&commit_data, &p2_decommit.commit_nonce) {
        return Err(Xal21Error::CommitmentVerification(
            "P_2 nonce commitment (f_2) verification failed".into(),
        ));
    }

    if !p2_decommit.nizk3.verify(&p2_decommit.R2, b"xal21-sign-R2") {
        return Err(Xal21Error::DlogVerification(
            "P_2 nonce DLog proof (nizk3) failed".into(),
        ));
    }

    let k1_R2 = p2_decommit.R2 * k1;
    let k1_r1_G = C::generator() * (k1 * step2_state.r1);
    let R = k1_R2 + k1_r1_G;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    Ok(Party1Presignature {
        k1,
        x1_prime: step2_state.x1_prime,
        r,
        R,
    })
}

pub fn offline_sign_generic<C: TecdsaCurve, M: MtA>(
    p1_key: &Xal21Party1KeyShare<C>,
    p2_key: &Xal21Party2KeyShare<C>,
    mta_setup: &M::Setup,
    rng: &mut impl CryptoRngCore,
) -> Result<(Party1Presignature<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let (step1_msg, step1_state) = step1_p2_commit::<C>(rng);

    let (sender_msg, sender_state) = step2_p2_encrypt_k2::<C, M>(mta_setup, &step1_state.k2, rng)?;

    let (step2_msg, step2_state) = step2_p1_compute::<C, M>(p1_key, mta_setup, &sender_msg, rng)?;

    let x2_prime = step2_p2_verify::<C, M>(
        p2_key,
        mta_setup,
        &sender_state,
        &step1_state.k2,
        &step2_msg,
    )?;

    let (step3_p1_msg, k1) = step3_p1_send_nonce::<C>(rng);

    let (step3_p2_decommit, p2_presig) =
        step3_p2_decommit_and_compute_R::<C>(&step1_state, &step3_p1_msg, &step2_msg.r1, x2_prime)?;

    let p1_presig =
        step3_p1_verify_and_compute_R::<C>(&step1_msg, &step3_p2_decommit, k1, &step2_state)?;

    debug_assert_eq!(p1_presig.r, p2_presig.r, "r mismatch between parties");

    Ok((p1_presig, p2_presig))
}

pub fn offline_sign<C: TecdsaCurve>(
    p1_key: &Xal21Party1KeyShare<C>,
    p2_key: &Xal21Party2KeyShare<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<(Party1Presignature<C>, Party2Presignature<C>), Xal21Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mta_setup = tecdsa_paillier::mta::PaillierMtaSetup {
        ek: p2_key.ek.clone(),
        dk: p2_key.dk.clone(),
        proof_setup: tecdsa_paillier::mta::Gg18ProofSetup {
            ntilde: p2_key.ntilde.clone(),
        },
    };

    offline_sign_generic::<C, DefaultMtA>(p1_key, p2_key, &mta_setup, rng)
}

fn serialize_point_and_proof<C: TecdsaCurve>(
    point: &C::ProjectivePoint,
    proof: &DlogProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut data = Vec::new();
    data.extend_from_slice(point.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

fn q_bytes<C: TecdsaCurve>() -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let q_int = curve_order::<C>();
    q_int.to_bytes_msf()
}
