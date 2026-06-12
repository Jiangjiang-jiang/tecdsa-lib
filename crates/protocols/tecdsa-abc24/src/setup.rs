use tecdsa_paillier::EncryptionKey;

#[derive(Clone)]
pub struct SetupData {
    pub ek: EncryptionKey,
}

impl SetupData {
    #[must_use]
    pub fn from_ek(ek: &EncryptionKey) -> Self {
        Self { ek: ek.clone() }
    }
}
