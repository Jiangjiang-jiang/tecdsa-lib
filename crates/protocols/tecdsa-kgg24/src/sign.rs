use elliptic_curve::{
    group::Curve as CurveGroup, ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes,
    FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_protocol::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::Kgg24Error,
    key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare},
    keygen::curve_order,
};

const TAU: u32 = 256;

const KAPPA: u32 = 80;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party1Round1Msg {
    pub commitment: HashCommitment,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2Round2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub r2: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party1Round3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub r1: C::ProjectivePoint,
    pub dlog_proof: DlogProof<C>,
    pub nonce: [u8; 32],
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Party2PartialSigMsg {
    pub c3: tecdsa_paillier::Ciphertext,
}

pub struct SignResult<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub signature: Signature<C>,
    pub needs_refresh: bool,
}

fn serialize_r1_and_proof<C: TecdsaCurve>(r1: &C::ProjectivePoint, proof: &DlogProof<C>) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::group::GroupEncoding;
    let mut data = Vec::new();
    data.extend_from_slice(r1.to_bytes().as_ref());
    data.extend_from_slice(proof.commitment.to_bytes().as_ref());
    data.extend_from_slice(proof.response.to_repr().as_ref());
    data
}

pub struct Party1SignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k1: C::Scalar,
    pub r1: C::ProjectivePoint,
}

pub fn party1_round1<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Party1Round1Msg, Party1SignState<C>, Party1Round3Msg<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k1 = C::random_scalar(rng);
    let r1 = C::generator() * k1;

    let ephemeral_nonce = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&k1, &ephemeral_nonce, &r1, b"kgg24-sign-r1");

    let commit_data = serialize_r1_and_proof::<C>(&r1, &dlog_proof);
    let (commitment, nonce) = HashCommitment::commit(&commit_data, rng);

    let msg = Party1Round1Msg { commitment };
    let state = Party1SignState { k1, r1 };
    let decommit = Party1Round3Msg {
        r1,
        dlog_proof,
        nonce,
    };

    (msg, state, decommit)
}

pub fn party1_round3<C: TecdsaCurve>(party2_msg: &Party2Round2Msg<C>) -> Result<(), Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if !party2_msg
        .dlog_proof
        .verify(&party2_msg.r2, b"kgg24-sign-r2")
    {
        return Err(Kgg24Error::DlogVerification(
            "Party 2 ephemeral DLog proof failed".into(),
        ));
    }
    Ok(())
}

pub fn party1_finalize<C: TecdsaCurve>(
    key_share: &Kgg24Party1KeyShare<C>,
    state: &Party1SignState<C>,
    party2_r2: &C::ProjectivePoint,
    party2_msg: &Party2PartialSigMsg,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignResult<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let r_point = *party2_r2 * state.k1;
    let r_affine = r_point.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    let s0_int = key_share
        .dk
        .decrypt(&party2_msg.c3)
        .map_err(|e| Kgg24Error::Paillier(format!("decryption failed: {e}")))?;

    let q_int = curve_order::<C>();
    let s1_int = s0_int.modulo_ref(&q_int);

    let ell_bound =
        &q_int * &q_int * tecdsa_paillier::backend::Integer::from(1u8).shl_ref(TAU + KAPPA);
    let ell = ell_bound.random_below_ref(rng);
    let s2_int = &s0_int - &s1_int + &ell * &q_int;

    let n = key_share.dk.encryption_key().n().clone();
    let divisor = tecdsa_paillier::backend::Integer::from(1u8).shl_ref(TAU + 2 * KAPPA);
    let threshold = &n / &divisor;

    let needs_refresh = if s2_int.cmp_abs(&threshold) == std::cmp::Ordering::Greater {
        true
    } else {
        let s2_mod_q = s2_int.modulo_ref(&q_int);
        s2_mod_q != tecdsa_paillier::backend::Integer::zero()
    };

    let s_prime_scalar = int_to_scalar::<C>(&s1_int);

    let k1_inv = state
        .k1
        .invert()
        .into_option()
        .ok_or_else(|| Kgg24Error::ProtocolState("k_1 is zero, cannot invert".into()))?;
    let s_double_prime = k1_inv * s_prime_scalar;

    let s = low_s_normalize::<C>(s_double_prime);

    let signature = Signature { r, s };

    verify_ecdsa::<C>(&signature, &key_share.public_key, message).map_err(|e| {
        Kgg24Error::EcdsaVerification(format!("final signature verification failed: {e}"))
    })?;

    Ok(SignResult {
        signature,
        needs_refresh,
    })
}

pub struct Party2SignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub k2: C::Scalar,
    pub r2: C::ProjectivePoint,
}

pub fn party2_round2<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Party2Round2Msg<C>, Party2SignState<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let k2 = C::random_scalar(rng);
    let r2 = C::generator() * k2;

    let ephemeral_nonce = C::random_scalar(rng);
    let dlog_proof = DlogProof::<C>::prove(&k2, &ephemeral_nonce, &r2, b"kgg24-sign-r2");

    let msg = Party2Round2Msg { r2, dlog_proof };
    let state = Party2SignState { k2, r2 };

    (msg, state)
}

pub fn party2_compute_partial_sig<C: TecdsaCurve>(
    key_share: &Kgg24Party2KeyShare<C>,
    state: &Party2SignState<C>,
    party1_round1: &Party1Round1Msg,
    party1_round3: &Party1Round3Msg<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Party2PartialSigMsg, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let commit_data = serialize_r1_and_proof::<C>(&party1_round3.r1, &party1_round3.dlog_proof);
    if !party1_round1
        .commitment
        .verify(&commit_data, &party1_round3.nonce)
    {
        return Err(Kgg24Error::CommitmentVerification(
            "Party 1 commitment opening failed".into(),
        ));
    }

    if !party1_round3
        .dlog_proof
        .verify(&party1_round3.r1, b"kgg24-sign-r1")
    {
        return Err(Kgg24Error::DlogVerification(
            "Party 1 ephemeral DLog proof failed".into(),
        ));
    }

    let r_point = party1_round3.r1 * state.k2;
    let r_affine = r_point.to_affine();
    let r = C::xcoord_mod_q(&r_affine);

    let k2_inv = state
        .k2
        .invert()
        .into_option()
        .ok_or_else(|| Kgg24Error::ProtocolState("k_2 is zero, cannot invert".into()))?;

    let q_int = curve_order::<C>();

    let rho_bar = q_int.random_below_ref(rng);
    let k2_inv_bytes = scalar_to_bytes::<C>(&k2_inv);
    let k2_inv_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&k2_inv_bytes);
    let k_tilde_2_inv = &k2_inv_int + &rho_bar * &q_int;

    let m_prime = *message.digest();
    let m_prime_bytes = scalar_to_bytes::<C>(&m_prime);
    let m_prime_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&m_prime_bytes);

    let r_bytes = scalar_to_bytes::<C>(&r);
    let r_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&r_bytes);

    let x2_bytes = scalar_to_bytes::<C>(&key_share.secret_share);
    let x2_int = tecdsa_paillier::backend::Integer::from_bytes_msf(&x2_bytes);

    let q_cubed = &q_int * &q_int * &q_int;
    let rho_bound =
        &q_cubed * 3u8 * tecdsa_paillier::backend::Integer::from(1u8).shl_ref(4 * TAU + 2 * KAPPA);
    let rho = rho_bound.random_below_ref(rng);

    let k_tilde_m = &k_tilde_2_inv * &m_prime_int;
    let k_tilde_r_x2 = &k_tilde_2_inv * &r_int * &x2_int;
    let partial_plaintext = &rho * &q_int + &k_tilde_m + &k_tilde_r_x2;

    let (c1, _nonce) = key_share
        .ek
        .encrypt_with_random(rng, &partial_plaintext)
        .map_err(|e| Kgg24Error::Paillier(format!("encryption of partial_sig failed: {e}")))?;

    let scalar_for_c = &r_int * &k_tilde_2_inv;
    let c2 = key_share
        .ek
        .omul(&scalar_for_c, &key_share.c_key)
        .map_err(|e| Kgg24Error::Paillier(format!("homomorphic scalar mult failed: {e}")))?;

    let c3 = key_share
        .ek
        .oadd(&c1, &c2)
        .map_err(|e| Kgg24Error::Paillier(format!("homomorphic addition failed: {e}")))?;

    Ok(Party2PartialSigMsg { c3 })
}

use tecdsa_curve::conv::scalar_to_bytes;

fn int_to_scalar<C: TecdsaCurve>(value: &tecdsa_paillier::backend::Integer) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    tecdsa_curve::conv::bytes_to_scalar::<C>(&value.to_bytes_msf())
}

pub fn sign<C: TecdsaCurve>(
    p1_key: &Kgg24Party1KeyShare<C>,
    p2_key: &Kgg24Party2KeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<SignResult<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    let (p1_round1_msg, p1_state, p1_decommit) = party1_round1::<C>(rng);

    let (p2_round2_msg, p2_state) = party2_round2::<C>(rng);

    party1_round3::<C>(&p2_round2_msg)?;

    let p2_partial_msg = party2_compute_partial_sig::<C>(
        p2_key,
        &p2_state,
        &p1_round1_msg,
        &p1_decommit,
        message,
        rng,
    )?;

    party1_finalize::<C>(
        p1_key,
        &p1_state,
        &p2_state.r2,
        &p2_partial_msg,
        message,
        rng,
    )
}

pub fn sign_simple<C: TecdsaCurve>(
    p1_key: &Kgg24Party1KeyShare<C>,
    p2_key: &Kgg24Party2KeyShare<C>,
    message: &DataToSign<C>,
    rng: &mut impl CryptoRngCore,
) -> Result<Signature<C>, Kgg24Error>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    sign(p1_key, p2_key, message, rng).map(|r| r.signature)
}

trait IntegerShlRef {
    fn shl_ref(&self, bits: u32) -> Self;
}

impl IntegerShlRef for tecdsa_paillier::backend::Integer {
    fn shl_ref(&self, bits: u32) -> Self {
        let two = tecdsa_paillier::backend::Integer::from(2u8);
        let shift = tecdsa_paillier::backend::Integer::u_pow_u(2, bits);
        let _ = two;
        self * &shift
    }
}
