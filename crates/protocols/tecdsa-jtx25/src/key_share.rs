// SPDX-License-Identifier: MIT OR Apache-2.0
use zeroize::Zeroize;

/// JTX25 key share produced after distributed key generation.
///
/// Contains the party's secret shares of both the ECDSA signing key and
/// the threshold CL decryption key, plus all public key material.
pub struct Jtx25KeyShare {
    /// This party's index (1-based).
    pub party_index: u16,
    /// Secret additive share x_i of the ECDSA signing key.
    pub secret_share: k256::Scalar,
    /// Joint ECDSA public key X = x * G.
    pub public_key: k256::ProjectivePoint,
    /// Public verification shares X_j = x_j * G for all parties.
    pub public_shares: Vec<k256::ProjectivePoint>,
    /// This party's threshold CL secret key share sk_i (big-endian bytes).
    pub cl_sk_share: Vec<u8>,
    /// Aggregate threshold CL public key pk.
    pub cl_pk: tecdsa_class_group::cl::ClPublicKey,
    /// Per-party CL public key shares pk_i = h^{sk_i}.
    pub cl_pk_shares: Vec<tecdsa_class_group::cl::Qfi>,
    /// Seed for recreating ClSetup.
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters.
    pub use_128bit_security: bool,
    /// Threshold t: need t+1 parties to sign.
    pub threshold: u16,
    /// Total parties n.
    pub total: u16,
    /// Total number of parties (for delta = n! computation).
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
