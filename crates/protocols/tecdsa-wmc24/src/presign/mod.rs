// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    non_snake_case
)]

//! WMC24 presigning protocol (3 rounds).
//!
//! Produces a message-independent [`Wmc24Presignature`] using threshold CL
//! homomorphic encryption and threshold ElGamal.

pub mod machine;
pub mod msg;
pub(crate) mod rounds;

pub use machine::Wmc24PresignMachine;
pub use msg::Wmc24PresignMsg;

use std::collections::BTreeMap;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Presignature output
// ---------------------------------------------------------------------------

/// Serialized class-group quadratic form element using compact binary encoding.
///
/// Uses the `Qfi::to_bytes`/`from_bytes` API from bicycl-rs v0.2.3 for
/// compact binary QFI serialization, replacing the previous verbose
/// `(a, b, c)` decimal string representation.
#[derive(Clone, Debug)]
pub struct QfiAbc {
    pub data: Vec<u8>,
}

/// Presignature produced by the WMC24 presign protocol.
///
/// CL ciphertexts are stored as pairs of [`QfiAbc`] (one per component).
/// See [`QfiAbc`] for details on the serialization format.
pub struct Wmc24Presignature {
    pub party_index: u16,
    /// R = (g^gamma)^{1/(gamma*k)} = g^{1/k}
    pub r_point: k256::ProjectivePoint,
    /// r_x = x_coord(R) mod q
    pub r_x: k256::Scalar,
    /// This party's k_i value.
    pub k_i: k256::Scalar,
    /// Number of signers.
    pub n_signers: usize,
    /// Threshold.
    pub threshold: u16,
    /// The combined k_bar ciphertext (c1, c2 components as QFI abc triples).
    pub k_bar_c1_abc: QfiAbc,
    pub k_bar_c2_abc: QfiAbc,
    /// The combined xk_bar ciphertext.
    pub xk_bar_c1_abc: QfiAbc,
    pub xk_bar_c2_abc: QfiAbc,
    /// CL setup seed.
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    /// Threshold CL secret key share (for partial decryption).
    pub cl_sk_share: Vec<u8>,
    /// Aggregate CL public key.
    pub cl_pk_abc: QfiAbc,
    /// Per-party CL PK shares.
    pub cl_pk_share_abcs: BTreeMap<u16, QfiAbc>,
    /// Total n for threshold CL (n_parties_dkg).
    pub n_parties_dkg: usize,
}

impl Clone for Wmc24Presignature {
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            r_point: self.r_point,
            r_x: self.r_x,
            k_i: self.k_i,
            n_signers: self.n_signers,
            threshold: self.threshold,
            k_bar_c1_abc: self.k_bar_c1_abc.clone(),
            k_bar_c2_abc: self.k_bar_c2_abc.clone(),
            xk_bar_c1_abc: self.xk_bar_c1_abc.clone(),
            xk_bar_c2_abc: self.xk_bar_c2_abc.clone(),
            cl_setup_seed: self.cl_setup_seed.clone(),
            use_128bit_security: self.use_128bit_security,
            cl_sk_share: self.cl_sk_share.clone(),
            cl_pk_abc: self.cl_pk_abc.clone(),
            cl_pk_share_abcs: self.cl_pk_share_abcs.clone(),
            n_parties_dkg: self.n_parties_dkg,
        }
    }
}

impl Zeroize for Wmc24Presignature {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.cl_sk_share.zeroize();
    }
}

impl Drop for Wmc24Presignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Wmc24Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wmc24Presignature")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}
