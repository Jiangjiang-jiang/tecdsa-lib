#[cfg(feature = "key-import")]
use rand_core::CryptoRngCore;
#[cfg(any(feature = "key-import", feature = "key-export"))]
use tecdsa_core::TecdsaError;

#[cfg(feature = "key-import")]
pub trait KeyImport: super::Protocol {
    fn import_key(
        secret_key: &[u8],
        threshold: u16,
        total: u16,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Self::KeyShare>, TecdsaError>;
}

#[cfg(feature = "key-export")]
pub trait KeyExport: super::Protocol {
    fn export_key(shares: &[Self::KeyShare]) -> Result<Vec<u8>, TecdsaError>;
}
