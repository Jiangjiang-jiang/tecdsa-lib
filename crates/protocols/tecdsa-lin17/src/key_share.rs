// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key share types for the Lin17 two-party ECDSA protocol.
//!
//! Lindell 2017 uses **multiplicative** key sharing: `x = x_1 * x_2`,
//! where P_1 holds `x_1` and P_2 holds `x_2`.
//!
//! P_1 also holds the Paillier decryption key, while P_2 holds the
//! Paillier encryption key and `c_key = Enc(x_1)`.

use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use zeroize::Zeroize;

/// Party 1 (server) key share.
///
/// Stores:
/// - `x_1`: multiplicative secret share
/// - `Q`: joint public key `Q = (x_1 * x_2) * G`
/// - `pk` / `sk`: Paillier key pair
pub struct Lin17Party1KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Multiplicative secret share `x_1`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `Q = x * G` where `x = x_1 * x_2`.
    pub public_key: C::ProjectivePoint,
    /// Paillier decryption key (secret).
    pub dk: DecryptionKey,
}

impl<C: TecdsaCurve> Zeroize for Lin17Party1KeyShare<C>
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
/// - `x_2`: multiplicative secret share
/// - `Q`: joint public key
/// - `c_key`: Paillier encryption of `x_1` under `pk`
/// - `pk`: Paillier encryption key (public)
pub struct Lin17Party2KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Multiplicative secret share `x_2`.
    pub secret_share: <C as CurveArithmetic>::Scalar,
    /// Joint ECDSA public key `Q = x * G` where `x = x_1 * x_2`.
    pub public_key: C::ProjectivePoint,
    /// Paillier encryption of Party 1's share: `c_key = Enc_pk(x_1)`.
    pub c_key: tecdsa_paillier::Ciphertext,
    /// Paillier encryption key (public).
    pub ek: EncryptionKey,
}

impl<C: TecdsaCurve> Zeroize for Lin17Party2KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}
