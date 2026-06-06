// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the XAL+21 two-party ECDSA protocol.
//!
//! XAL+21 uses **additive** key sharing: `x = x_1 + x_2`,
//! where P_1 holds `x_1` and P_2 holds `x_2`.
//!
//! P_2 holds the Paillier key pair (decryption key) for the MtA protocol,
//! while P_1 holds only the Paillier encryption key.
//!
//! In XAL+21's MtA, P_2 encrypts its input `k_2` and sends it to P_1,
//! so P_2 must own the decryption key to receive the MtA result.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

/// Party 1 (server) key share.
///
/// Stores:
/// - `x_1`: additive secret share
/// - `Q`: joint public key `Q = (x_1 + x_2) * G`
/// - `ek`: Paillier encryption key (public, from P_2)
/// - `ntilde`: Ring-Pedersen auxiliary parameters for MtA range proofs
pub struct Xal21Party1KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Additive secret share `x_1`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `Q = x * G` where `x = x_1 + x_2`.
    pub public_key: C::ProjectivePoint,
    /// Public key of Party 1: `Q_1 = x_1 * G`.
    pub public_share: C::ProjectivePoint,
    /// Paillier encryption key (public, owned by P_2).
    pub ek: EncryptionKey,
    /// Ring-Pedersen auxiliary parameters for MtA range proofs.
    pub ntilde: NTildeParams,
}

impl<C: TecdsaCurve> Zeroize for Xal21Party1KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

/// Party 2 (client) key share.
///
/// Stores:
/// - `x_2`: additive secret share
/// - `Q`: joint public key
/// - `Q_1`: public key of Party 1 (needed for consistency check)
/// - `dk`: Paillier decryption key (secret)
/// - `ek`: Paillier encryption key (public)
/// - `ntilde`: Ring-Pedersen auxiliary parameters for MtA range proofs
pub struct Xal21Party2KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Additive secret share `x_2`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `Q = x * G` where `x = x_1 + x_2`.
    pub public_key: C::ProjectivePoint,
    /// Public key of Party 1: `Q_1 = x_1 * G`.
    pub public_share_p1: C::ProjectivePoint,
    /// Paillier decryption key (secret, for MtA).
    pub dk: DecryptionKey,
    /// Paillier encryption key (public).
    pub ek: EncryptionKey,
    /// Ring-Pedersen auxiliary parameters for MtA range proofs.
    pub ntilde: NTildeParams,
}

impl<C: TecdsaCurve> Zeroize for Xal21Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
