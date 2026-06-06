// SPDX-License-Identifier: MIT OR Apache-2.0
//! LLZ25 key share type.
//!
//! After key generation, each party holds:
//! - A Shamir share $x_i$ of the signing key $x$
//! - A public verification share $X_i = x_i \cdot G$
//! - A NIM `Encode_B` ciphertext $pe_{x,i}$ (CL encryption of $x_i$)
//! - The NIM state $st_{x,i}$ (encryption randomness)
//! - The joint public key $X = x \cdot G$

use zeroize::Zeroize;

/// A single party's key share for LLZ25.
#[derive(Clone)]
pub struct Llz25KeyShare {
    /// This party's 1-based index.
    pub party_index: u16,
    /// Secret Shamir share $x_i$.
    pub secret_share: k256::Scalar,
    /// Joint ECDSA public key $X = x \cdot G$.
    pub public_key: k256::ProjectivePoint,
    /// Public verification shares $X_j = x_j \cdot G$ for all parties (1-indexed).
    pub public_shares: Vec<k256::ProjectivePoint>,
    /// NIM `Encode_B` state (encryption randomness for $pe_{x,i}$).
    /// This is the secret key material for NIM decoding in the sign phase.
    pub st_x_bytes: Vec<u8>,
    /// This party's $pe_{x,i}$ ciphertext components (c1_a, c1_b, c1_c, c2_a, c2_b, c2_c).
    pub pe_x_components: (String, String, String, String, String, String),
    /// All parties' $pe_{x,j}$ ciphertext components, needed for NIM decoding in sign phase.
    pub all_pe_x_components: Vec<(String, String, String, String, String, String)>,
    /// Seed for CL setup recreation.
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters.
    pub use_128bit_security: bool,
    /// Threshold $t$: need $t+1$ parties to sign.
    pub threshold: u16,
    /// Total parties $n$.
    pub total: u16,
}

impl Llz25KeyShare {
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

impl Zeroize for Llz25KeyShare {
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
        self.st_x_bytes.zeroize();
        self.cl_setup_seed.zeroize();
    }
}

impl Drop for Llz25KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Llz25KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Llz25KeyShare")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
