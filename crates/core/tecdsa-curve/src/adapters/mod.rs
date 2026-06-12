#[cfg(feature = "secp256k1")]
mod secp256k1;
#[cfg(feature = "secp256r1")]
mod secp256r1;

#[cfg(feature = "secp256k1")]
pub use self::secp256k1::Secp256k1Adapter;
#[cfg(feature = "secp256r1")]
pub use self::secp256r1::Secp256r1Adapter;
