// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trout key share type.
//!
//! After key generation (trusted dealer), each party holds:
//! - `x_i`: Shamir share of the signing key
//! - `delta_i`: CL encryption randomness for the share encryption
//! - `evrf_sk`: eVRF secret key
//! - `C_tilde_i`: CL encryption of x_i under the joint CL public key
//!
//! The joint CL public key `Y_cl` is randomly sampled in `G_q`.

use tecdsa_evrf::{EvrfPublicKey, EvrfSecretKey};
use zeroize::Zeroize;

/// A single party's key share produced by Trout key generation.
pub struct TroutKeyShare {
    /// This party's 1-based index.
    pub party_index: u16,
    /// Secret Shamir share x_i of the ECDSA signing key.
    pub secret_share: k256::Scalar,
    /// CL encryption randomness delta_i used to encrypt x_i.
    pub delta_i: Vec<u8>,
    /// eVRF secret key for this party.
    pub evrf_sk: EvrfSecretKey<k256::Secp256k1>,
    /// eVRF public key for this party.
    pub evrf_pk: EvrfPublicKey<k256::Secp256k1>,
    /// All parties' eVRF public keys (indexed 0..n-1).
    pub all_evrf_pks: Vec<EvrfPublicKey<k256::Secp256k1>>,
    /// Joint ECDSA public key X = x * G.
    pub public_key: k256::ProjectivePoint,
    /// Public verification shares X_j = x_j * G for all parties.
    pub public_shares: Vec<k256::ProjectivePoint>,
    /// Serialised CL encryption of x_i: C_tilde_i = Enc(delta_i, x_i).
    /// Stored as (c1_a, c1_b, c1_c, c2_a, c2_b, c2_c) decimal strings.
    pub ct_share_components: (String, String, String, String, String, String),
    /// All parties' CL encryption components for their shares.
    pub all_ct_share_components: Vec<(String, String, String, String, String, String)>,
    /// The joint CL public key element serialised as (a, b, c) decimal strings.
    /// This is needed to reconstruct the CL public key for use in presign/sign.
    pub cl_pk_abc: (String, String, String),
    /// CL setup seed for recreating ClSetup.
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters.
    pub use_128bit_security: bool,
    /// Threshold t: at least t+1 parties needed.
    pub threshold: u16,
    /// Total parties n.
    pub total: u16,
}

impl TroutKeyShare {
    /// Recreate a `ClSetup` from the stored seed.
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
