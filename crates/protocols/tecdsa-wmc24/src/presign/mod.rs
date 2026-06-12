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

pub mod machine;
pub mod msg;
pub(crate) mod rounds;

use std::collections::BTreeMap;

pub use machine::Wmc24PresignMachine;
pub use msg::Wmc24PresignMsg;
use tecdsa_core::TecdsaError;
use tecdsa_protocol::PartyId;
use zeroize::Zeroize;

pub(crate) fn party_id_to_dkg_idx(pid: PartyId) -> tecdsa_core::Result<usize> {
    pid.0
        .checked_sub(1)
        .map(|v| v as usize)
        .ok_or_else(|| TecdsaError::Other("invalid PartyId(0): expected 1-based".into()))
}

#[derive(Clone, Debug)]
pub struct QfiAbc {
    pub data: Vec<u8>,
}

pub struct Wmc24Presignature {
    pub party_index: u16,
    pub r_point: k256::ProjectivePoint,
    pub r_x: k256::Scalar,
    pub k_i: k256::Scalar,
    pub n_signers: usize,
    pub threshold: u16,
    pub k_bar_c1_abc: QfiAbc,
    pub k_bar_c2_abc: QfiAbc,
    pub xk_bar_c1_abc: QfiAbc,
    pub xk_bar_c2_abc: QfiAbc,
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    pub cl_sk_share: Vec<u8>,
    pub cl_pk_abc: QfiAbc,
    pub cl_pk_share_abcs: BTreeMap<u16, QfiAbc>,
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
