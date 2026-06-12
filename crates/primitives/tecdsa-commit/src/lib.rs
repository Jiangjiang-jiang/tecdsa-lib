#![doc = "Hash and Pedersen-EC commitments for the tecdsa threshold ECDSA library."]

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashCommitment {
    hash: [u8; 32],
}

impl HashCommitment {
    pub fn commit(message: &[u8], rng: &mut impl CryptoRngCore) -> (Self, [u8; 32]) {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        let hash = Sha256::new()
            .chain_update(nonce)
            .chain_update(message)
            .finalize()
            .into();
        (Self { hash }, nonce)
    }

    #[must_use]
    pub fn verify(&self, message: &[u8], nonce: &[u8; 32]) -> bool {
        let expected: [u8; 32] = Sha256::new()
            .chain_update(nonce)
            .chain_update(message)
            .finalize()
            .into();
        self.hash == expected
    }
}

#[derive(Debug, Clone)]
pub struct PedersenCommitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub point: C::ProjectivePoint,
    pub randomness: C::Scalar,
}

impl<C: TecdsaCurve> PedersenCommitment<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn commit_scalar(value: &C::Scalar, rng: &mut impl CryptoRngCore) -> Self {
        let randomness = C::random_scalar(rng);
        let g = C::generator();
        let h = C::nums_pedersen_h();
        let point = g * value + h * randomness;
        Self { point, randomness }
    }

    #[must_use]
    pub fn verify_scalar(&self, value: &C::Scalar) -> bool {
        let expected = C::generator() * value + C::nums_pedersen_h() * self.randomness;
        self.point == expected
    }
}
