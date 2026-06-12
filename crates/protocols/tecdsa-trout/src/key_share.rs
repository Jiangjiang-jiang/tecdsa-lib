use tecdsa_evrf::{EvrfPublicKey, EvrfSecretKey};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct TroutKeyShare {
    pub party_index: u16,
    pub secret_share: k256::Scalar,
    pub delta_i: Vec<u8>,
    pub evrf_sk: EvrfSecretKey<k256::Secp256k1>,
    pub evrf_pk: EvrfPublicKey<k256::Secp256k1>,
    pub all_evrf_pks: Vec<EvrfPublicKey<k256::Secp256k1>>,
    pub public_key: k256::ProjectivePoint,
    pub public_shares: Vec<k256::ProjectivePoint>,
    pub ct_share_components: (String, String, String, String, String, String),
    pub all_ct_share_components: Vec<(String, String, String, String, String, String)>,
    pub cl_pk_abc: (String, String, String),
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    pub threshold: u16,
    pub total: u16,
}

impl TroutKeyShare {
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

impl Zeroize for TroutKeyShare {
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.delta_i.zeroize();
        self.evrf_sk.zeroize();
        self.cl_setup_seed.zeroize();
    }
}

impl Drop for TroutKeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for TroutKeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TroutKeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
