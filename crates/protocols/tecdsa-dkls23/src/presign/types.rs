// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::key_share::Dkls23KeyShare;

/// RVOLE correlation data that party i holds for counterparty j.
///
/// For a given pair (i, j) the correlation satisfies:
///   c_u + d_u = chi * r_j (mod q)    -- nonce product
///   c_v + d_v = chi * sk_j (mod q)   -- key product
///
/// When using the real OT-based RVOLE:
///   - Party i (MulReceiver) gets chi (= b), d_u, d_v (= receiver_output)
///   - Party j (MulSender) gets c_u, c_v (= sender_output)
///
/// After the RVOLE completes, each party holds BOTH the Alice-side (chi, c_u, c_v)
/// and the Bob-side (d_u, d_v) data from the two opposite-direction instances.
#[derive(Clone)]
pub struct PartyRvoleData<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Random multiplier chi_{i,j} from the instance where i is MulReceiver.
    pub chi: <C as CurveArithmetic>::Scalar,
    /// Sender's nonce product share c^u_{j,i} from the instance where j is MulSender.
    pub c_u: <C as CurveArithmetic>::Scalar,
    /// Sender's key product share c^v_{j,i} from the instance where j is MulSender.
    pub c_v: <C as CurveArithmetic>::Scalar,
    /// Receiver's nonce product share d^u_{j,i} from the instance where i is MulReceiver
    /// in the (j as Alice, i as Bob) direction.
    pub d_u: <C as CurveArithmetic>::Scalar,
    /// Receiver's key product share d^v_{j,i} from the instance where i is MulReceiver
    /// in the (j as Alice, i as Bob) direction.
    pub d_v: <C as CurveArithmetic>::Scalar,
}

impl<C: TecdsaCurve> Zeroize for PartyRvoleData<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.chi.zeroize();
        self.c_u.zeroize();
        self.c_v.zeroize();
        self.d_u.zeroize();
        self.d_v.zeroize();
    }
}

impl<C: TecdsaCurve> Drop for PartyRvoleData<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Presignature output from DKLs23 presigning (3 rounds).
///
/// Contains all per-party state needed for the 1-round online signing phase,
/// including the combined nonce point R, the x-coordinate r, and RVOLE
/// correlation data for each counterparty.
///
/// Unlike Paillier-based protocols, DKLs23 presignatures do not contain
/// any ciphertexts -- all multiplication is done via OT/VOLE, producing
/// additive shares directly.
#[derive(Clone)]
pub struct Dkls23Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's identifier.
    pub my_id: PartyId,
    /// The signing subset party IDs.
    pub signer_parties: Vec<PartyId>,
    /// This party's nonce share r_i.
    pub r_i: <C as CurveArithmetic>::Scalar,
    /// This party's inversion mask phi_i.
    pub phi_i: <C as CurveArithmetic>::Scalar,
    /// This party's Lagrange-weighted key share: sk_i = lambda_i * share_i.
    pub sk_i: <C as CurveArithmetic>::Scalar,
    /// Public key corresponding to sk_i: pk_i = sk_i * G.
    pub pk_i: C::ProjectivePoint,
    /// Combined nonce point R = sum(R_j) for all j in signing set.
    pub R: C::ProjectivePoint,
    /// x-coordinate of R reduced mod the group order.
    pub r_x: <C as CurveArithmetic>::Scalar,
    /// RVOLE correlation data per counterparty (keyed by counterparty's PartyId.0).
    pub rvole_data: BTreeMap<u16, PartyRvoleData<C>>,
    /// Received psi values from counterparties: psi_{j,i} for each j.
    pub received_psi: BTreeMap<u16, <C as CurveArithmetic>::Scalar>,
    /// The original key share (needed for public key verification).
    pub key_share: Dkls23KeyShare<C>,
}

impl<C: TecdsaCurve> Zeroize for Dkls23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.r_i.zeroize();
        self.phi_i.zeroize();
        self.sk_i.zeroize();
        for data in self.rvole_data.values_mut() {
            data.zeroize();
        }
    }
}

impl<C: TecdsaCurve> Drop for Dkls23Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An ideal RVOLE correlation between two parties (for testing).
///
/// For parties (P_i as Alice, P_j as Bob) with Bob's private inputs (r_j, sk_j),
/// the correlation satisfies:
///   c_u + d_u = chi * r_j  (mod q)
///   c_v + d_v = chi * sk_j (mod q)
///
/// In the ideal model, a trusted dealer samples chi, d_u, d_v at random,
/// then computes c_u = chi * r_j - d_u and c_v = chi * sk_j - d_v.
#[derive(Clone)]
pub struct RvoleCorrelation<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Alice's random multiplier.
    pub chi: <C as CurveArithmetic>::Scalar,
    /// Alice's nonce product share.
    pub c_u: <C as CurveArithmetic>::Scalar,
    /// Alice's key product share.
    pub c_v: <C as CurveArithmetic>::Scalar,
    /// Bob's nonce product share.
    pub d_u: <C as CurveArithmetic>::Scalar,
    /// Bob's key product share.
    pub d_v: <C as CurveArithmetic>::Scalar,
}

/// Generate an ideal RVOLE correlation for testing.
///
/// Simulates the ideal RVOLE functionality F_RVOLE:
/// - Samples chi uniformly at random
/// - Samples d_u, d_v uniformly at random
/// - Computes c_u = chi * r_bob - d_u
/// - Computes c_v = chi * sk_bob - d_v
///
/// This lets us validate the signing protocol logic independently from
/// the underlying OT-based RVOLE sub-protocol.
pub fn ideal_rvole<C: TecdsaCurve>(
    r_bob: &<C as CurveArithmetic>::Scalar,
    sk_bob: &<C as CurveArithmetic>::Scalar,
    rng: &mut impl rand_core::CryptoRngCore,
) -> RvoleCorrelation<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: elliptic_curve::PrimeField<Repr = elliptic_curve::FieldBytes<C>>,
{
    let chi = C::random_scalar(rng);
    let d_u = C::random_scalar(rng);
    let d_v = C::random_scalar(rng);
    let c_u = chi * *r_bob - d_u;
    let c_v = chi * *sk_bob - d_v;
    RvoleCorrelation {
        chi,
        c_u,
        c_v,
        d_u,
        d_v,
    }
}
