// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{collections::BTreeMap, sync::Arc};

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

use crate::{f_mult::input::InputOutput, sign::mta_hybrid::Ln18MtaHybrid};

/// Key share for the LN18 protocol (Feldman VSS DKG).
///
/// Contains the Shamir secret share, the joint ECDSA public key,
/// and per-party public verification shares.
pub struct Ln18KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    /// Shamir secret share f(party_id), where f is the combined VSS polynomial.
    pub secret_share: C::Scalar,
    /// Joint ECDSA public key Q = x*G (sum of all constant terms).
    pub public_key: C::ProjectivePoint,
    /// Per-party public verification shares X_j = f(j)*G.
    pub public_shares: Vec<C::ProjectivePoint>,
    /// Number of parties.
    pub n: u16,
    /// Corruption threshold t (signing quorum = t+1).
    pub t: u16,
}

impl<C: TecdsaCurve> Clone for Ln18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            secret_share: self.secret_share,
            public_key: self.public_key,
            public_shares: self.public_shares.clone(),
            n: self.n,
            t: self.t,
        }
    }
}

impl<C: TecdsaCurve> Zeroize for Ln18KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
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
/// - `stored_x_input`: the per-session Lagrange-weighted x input state (for affine)
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
    /// Per-session Lagrange-weighted x input state, needed for affine(x, r, m') in the online phase.
    pub stored_x_input: InputOutput<C>,
    /// ElGamal decryption key share d_i.
    pub elgamal_dk: C::Scalar,
    /// Joint ElGamal public key P.
    pub elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public key shares P_j = d_j*G.
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
}

/// Carry state produced by LN18 signing rounds 1-2 (offline phase).
///
/// This state is message-independent. It contains completed `input(k)` and
/// `input(rho)` outputs plus the key material needed by online rounds 3-8.
/// For t-of-n signing, `weighted_x_input` is the Lagrange-weighted key input
/// for this signing subset.
#[allow(non_snake_case)]
pub struct Ln18OfflineSignState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    pub my_id: PartyId,
    /// All parties in the protocol (superset of signers).
    pub all_parties: Vec<PartyId>,
    /// Completed input(k) output.
    pub input_k: InputOutput<C>,
    /// Completed input(rho) output.
    pub input_rho: InputOutput<C>,
    /// This party's Paillier decryption key.
    pub paillier_dk: DecryptionKey,
    /// Paillier encryption keys for all signer parties.
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    /// Ring-Pedersen auxiliary parameters for all signer parties.
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    /// Per-session Lagrange-weighted x input for this signer subset.
    pub stored_x_input: InputOutput<C>,
    /// The signer subset for this signing session.
    pub signer_parties: Vec<PartyId>,
    /// Lagrange-weighted x input for this signer subset.
    pub weighted_x_input: InputOutput<C>,
    /// ElGamal decryption key share d_i.
    pub elgamal_dk: C::Scalar,
    /// Joint ElGamal public key P.
    pub elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public key shares.
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
    /// Shared MtA provider for this signing session.
    pub mta: Arc<Ln18MtaHybrid<C>>,
}

impl<C: TecdsaCurve> Zeroize for Ln18OfflineSignState<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.input_k.a_i.zeroize();
        self.input_k.s_i.zeroize();
        self.input_rho.a_i.zeroize();
        self.input_rho.s_i.zeroize();
        self.weighted_x_input.a_i.zeroize();
        self.weighted_x_input.s_i.zeroize();
        self.elgamal_dk.zeroize();
    }
}
