// SPDX-License-Identifier: MIT OR Apache-2.0
use zeroize::Zeroize;

/// WMC24 key share produced after distributed key generation.
///
/// Contains the party's secret shares of:
/// - ECDSA signing key (x_i)
/// - Threshold CL decryption key (cl_sk_share)
/// - Threshold ElGamal decryption key (eldk_i)
///
/// Plus all public key material.
pub struct Wmc24KeyShare {
    /// This party's index (1-based).
    pub party_index: u16,
    /// Secret additive share x_i of the ECDSA signing key.
    pub secret_share: k256::Scalar,
    /// Joint ECDSA public key X = x * G.
    pub public_key: k256::ProjectivePoint,
    /// Public verification shares X_j = x_j * G for all parties.
    pub public_shares: Vec<k256::ProjectivePoint>,
    /// This party's threshold CL secret key share sk_i (decimal string).
    pub cl_sk_share: Vec<u8>,
    /// Aggregate threshold CL public key pk.
    pub cl_pk: tecdsa_class_group::cl::ClPublicKey,
    /// Per-party CL public key shares pk_i = h^{sk_i}.
    pub cl_pk_shares: Vec<tecdsa_class_group::cl::Qfi>,
    /// Seed for recreating ClSetup.
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters.
    pub use_128bit_security: bool,
    /// This party's ElGamal decryption key share eldk_i.
    pub eldk_i: k256::Scalar,
    /// Per-party ElGamal public key shares elek_j = eldk_j * G.
    pub elek_shares: Vec<k256::ProjectivePoint>,
    /// Aggregate ElGamal public key elek = sum(elek_j).
    pub elek: k256::ProjectivePoint,
    /// Threshold t: need t+1 parties to sign.
    pub threshold: u16,
    /// Total parties n.
    pub total: u16,
    /// Total number of parties (for delta = n! computation).
    pub n_parties_dkg: usize,
}

impl Wmc24KeyShare {
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

impl Zeroize for Wmc24KeyShare {
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.cl_sk_share.zeroize();
        self.cl_setup_seed.zeroize();
        self.eldk_i.zeroize();
    }
}

impl Drop for Wmc24KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Wmc24KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wmc24KeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
