// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 key share type.
//!
//! After key generation, each party holds an additive share $x_i$ of the
//! signing key $x$, a CL-HSM key pair for MtAwc, and the joint public key.
//!
//! # Design note (v0.2.2 refactor)
//!
//! As of bicycl-rs v0.2.2, all CL types including `ClSetup` implement
//! `Send`.  The key share stores CL key material directly, and callers
//! can store `ClSetup` in structs that cross thread boundaries.
//!
//! The `cl_setup_seed` and `use_128bit_security` fields are kept for
//! backward compatibility (e.g., creating a fresh `ClSetup` from a
//! serialized key share), but protocol state machines now store `ClSetup`
//! directly instead of recreating it per round.

use tecdsa_class_group::cl::{ClPublicKey, ClSecretKey};
use zeroize::Zeroize;

/// A single party's key share produced by WMY23 key generation.
///
/// Contains the party's secret additive share $x_i$, the joint public key
/// $X = g^x$, per-party CL-HSM key material for CL-based MtAwc, and the
/// seed needed to recreate a `ClSetup` per session.
#[derive(Clone)]
pub struct Wmy23KeyShare {
    /// This party's index (1-based).
    pub party_index: u16,
    /// Secret additive share $x_i$ of the ECDSA signing key.
    pub secret_share: k256::Scalar,
    /// Joint ECDSA public key $X = x \cdot G$.
    pub public_key: k256::ProjectivePoint,
    /// Public verification shares $X_j = x_j \cdot G$ for all parties.
    pub public_shares: Vec<k256::ProjectivePoint>,
    /// This party's CL-HSM secret key (now stored directly; `Send` since
    /// bicycl-rs v0.2.1).
    pub cl_sk: ClSecretKey,
    /// All parties' CL-HSM public keys (indexed 0..n-1).  Stored directly
    /// since `ClPublicKey` is now `Send`.
    pub cl_pks: Vec<ClPublicKey>,
    /// Seed string used to recreate `ClSetup` when needed (e.g., from
    /// a serialized key share).  Since bicycl-rs v0.2.2, `ClSetup` is
    /// `Send` and protocol machines store it directly.
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters (1828-bit discriminant).
    /// If false, uses the insecure p=7 parameters (for fast testing only).
    pub use_128bit_security: bool,
    /// Threshold $t$: at least $t+1$ parties needed.
    pub threshold: u16,
    /// Total parties $n$.
    pub total: u16,
}

impl Wmy23KeyShare {
    /// Recreate a `ClSetup` from the stored seed, using the correct
    /// security parameters (128-bit or insecure/test).
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
        // ClSecretKey cleanup is handled by the BICYCL C library's
        // destructor when it is dropped.  We cannot additionally zero
        // the C-side allocation without unsafe, but the drop impl in
        // bicycl-rs frees the memory.
        //
        // The seed string is zeroized here since it can be used to
        // reconstruct the CL setup and derive keys.
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
