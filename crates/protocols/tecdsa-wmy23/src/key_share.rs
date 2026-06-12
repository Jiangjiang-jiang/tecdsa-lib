use tecdsa_class_group::cl::{ClPublicKey, ClSecretKey};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Wmy23KeyShare {
    pub party_index: u16,
    pub secret_share: k256::Scalar,
    pub public_key: k256::ProjectivePoint,
    pub public_shares: Vec<k256::ProjectivePoint>,
    pub cl_sk: ClSecretKey,
    pub cl_pks: Vec<ClPublicKey>,
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    pub threshold: u16,
    pub total: u16,
}

impl Wmy23KeyShare {
    pub fn create_cl_setup(
        &self,
    ) -> Result<tecdsa_class_group::cl::ClSetup, tecdsa_class_group::cl::ClError> {
        if self.use_128bit_security {
            tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit(&self.cl_setup_seed)
        } else {
            tecdsa_class_group::cl::ClSetup::new_secp256k1(&self.cl_setup_seed)
        }
    }
}

impl Zeroize for Wmy23KeyShare {
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.cl_setup_seed.zeroize();
    }
}

impl Drop for Wmy23KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Wmy23KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wmy23KeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
