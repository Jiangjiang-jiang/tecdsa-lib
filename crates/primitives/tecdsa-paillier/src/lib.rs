pub mod conv;
#[allow(non_snake_case)]
pub mod mta;
pub mod threshold;
pub mod zk;

pub use fast_paillier::{
    backend, AnyEncryptionKey, AnyEncryptionKeyExt, Ciphertext, DecryptionKey, EncryptionKey,
    Error as PaillierError, Nonce, Plaintext,
};
use rand_core::{CryptoRng, RngCore};

pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<DecryptionKey, PaillierError> {
    DecryptionKey::generate(rng)
}

pub fn encrypt<E: AnyEncryptionKey>(
    ek: &E,
    rng: &mut (impl RngCore + CryptoRng),
    plaintext: &Plaintext,
) -> Result<(Ciphertext, Nonce), PaillierError> {
    ek.encrypt_with_random(rng, plaintext)
}

pub fn decrypt(dk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<Plaintext, PaillierError> {
    dk.decrypt(ciphertext)
}

pub fn add_ciphertexts(
    ek: &dyn AnyEncryptionKey,
    c1: &Ciphertext,
    c2: &Ciphertext,
) -> Result<Ciphertext, PaillierError> {
    ek.oadd(c1, c2)
}

pub fn scalar_mul_ciphertext(
    ek: &dyn AnyEncryptionKey,
    scalar: &backend::Integer,
    ciphertext: &Ciphertext,
) -> Result<Ciphertext, PaillierError> {
    ek.omul(scalar, ciphertext)
}
