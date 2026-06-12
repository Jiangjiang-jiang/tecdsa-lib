use zeroize::Zeroize;

pub struct Jtx25KeyShare {
    pub party_index: u16,
    pub secret_share: k256::Scalar,
    pub public_key: k256::ProjectivePoint,
    pub public_shares: Vec<k256::ProjectivePoint>,
    pub cl_sk_share: Vec<u8>,
    pub cl_pk: tecdsa_class_group::cl::ClPublicKey,
    pub cl_pk_shares: Vec<tecdsa_class_group::cl::Qfi>,
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    pub threshold: u16,
    pub total: u16,
    pub n_parties_dkg: usize,
}

impl Jtx25KeyShare {
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

impl Zeroize for Jtx25KeyShare {
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.cl_sk_share.zeroize();
        self.cl_setup_seed.zeroize();
    }
}

impl Drop for Jtx25KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Jtx25KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jtx25KeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
