// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the ABC+24 two-party ECDSA protocol.
//!
//! ABC+24 uses **additive** key sharing: `x = x_1 + x_2`,
//! where Server (P_1) holds `x_2` and Client (P_2) holds `x_1`.
//!
//! The server holds the Paillier decryption key and `phi(N)`.
//! The client holds a Paillier ciphertext `E = enc_N(x_2)` of the server's share.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

use crate::setup::SetupData;

/// Server (P_1) key share.
///
/// The server holds the Paillier private key and its additive share `x_2`.
/// In the paper, the server generates the setup material (Paillier key, DF params)
/// once and reuses it across multiple clients.
pub struct Abc24ServerKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Additive secret share `x_2 = x'_2 mod q`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `X = g^{x_1 + x_2}`.
    pub public_key: C::ProjectivePoint,
    /// Client's public key share `X_1 = g^{x_1}`.
    pub client_public_share: C::ProjectivePoint,
    /// Paillier decryption key.
    pub dk: DecryptionKey,
    /// Setup data (public parameters).
    pub setup: SetupData,
}

impl<C: TecdsaCurve> Zeroize for Abc24ServerKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

/// Client (P_2) key share.
///
/// The client holds its additive share `x_1` and a Paillier encryption
/// `E = enc_N(x_2)` of the server's share under the server's Paillier key.
pub struct Abc24ClientKeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Additive secret share `x_1`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `X = g^{x_1 + x_2}`.
    pub public_key: C::ProjectivePoint,
    /// Server's public key share `X_2 = g^{x_2}`.
    pub server_public_share: C::ProjectivePoint,
    /// Paillier encryption of server's share: `E = enc_N(x_2; rho^beta)`.
    pub enc_x2: tecdsa_paillier::Ciphertext,
    /// Paillier encryption key (server's public key).
    pub ek: EncryptionKey,
    /// Setup data (public parameters).
    pub setup: SetupData,
}

impl<C: TecdsaCurve> Zeroize for Abc24ClientKeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
