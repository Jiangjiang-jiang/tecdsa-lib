// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::f_mult::input::InputOutput;

/// Key share for the LN18 protocol.
///
/// Contains the ECDSA secret share, the ElGamal keypair shares,
/// and all parties' ElGamal public key shares.
pub struct Ln18KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    /// ECDSA secret share x_i (sum x_i = x, the signing key)
    pub secret_share: C::Scalar,
    /// Joint ECDSA public key Q = x*G
    pub public_key: C::ProjectivePoint,
    /// ElGamal decryption key share d_i
    pub elgamal_dk: C::Scalar,
    /// Joint ElGamal public key P = d*G
    pub elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public key shares P_j = d_j*G
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
    /// Number of parties
    pub n: u16,
    /// Threshold (t+1 parties needed to sign)
    pub t: u16,
}

impl<C: TecdsaCurve> Zeroize for Ln18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.elgamal_dk.zeroize();
    }
}

#[allow(non_snake_case)]
/// Output of the LN18 offline presigning phase.
///
/// After the offline phase, each party holds:
/// - `R`: the nonce point R = k*G
/// - `r`: the x-coordinate of R mod q (the ECDSA r-value)
/// - `tau_i`: their additive share of tau = k*rho (from mult(k, rho))
/// - `stored_rho_input`: the rho input state needed for the second multiplication
/// - `stored_x_input`: the x input state from KeyGen (for affine)
/// - ElGamal key material (d_i, P, pk_shares) for mult
///
/// This presignature is message-independent and can be computed offline.
/// The online phase takes this plus the message digest to produce a signature.
pub struct Ln18Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Nonce point R = k*G.
    pub R: C::ProjectivePoint,
    /// ECDSA r-value: x-coordinate of R mod q.
    pub r: C::Scalar,
    /// This party's share of tau = k*rho.
    pub tau_i: C::Scalar,
    /// Stored rho input state, needed for mult(rho, alpha) in the online phase.
    pub stored_rho_input: InputOutput<C>,
    /// Stored x input state from KeyGen, needed for affine(x, r, m') in the online phase.
    pub stored_x_input: InputOutput<C>,
    /// ElGamal decryption key share d_i.
    pub elgamal_dk: C::Scalar,
    /// Joint ElGamal public key P.
    pub elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public key shares P_j = d_j*G.
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
}
