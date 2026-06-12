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
pub mod rounds;

use std::collections::BTreeMap;

pub use machine::Tx25PresignMachine;
pub use msg::Tx25PresignMsg;
use tecdsa_class_group::cl::ClPublicKey;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Tx25Presignature {
    pub r_point: k256::ProjectivePoint,
    pub r_x: k256::Scalar,
    pub k_share: k256::Scalar,
    pub gamma_i: k256::Scalar,
    pub sigma_share: k256::Scalar,
    pub delta_shares: BTreeMap<u16, k256::Scalar>,
    pub zeta_shares: BTreeMap<u16, k256::Scalar>,
    pub b_points: BTreeMap<(u16, u16), k256::ProjectivePoint>,
    pub b_hat_points: BTreeMap<(u16, u16), k256::ProjectivePoint>,
    pub party_index: u16,
    pub threshold: u16,
}

impl Zeroize for Tx25Presignature {
    fn zeroize(&mut self) {
        self.k_share.zeroize();
        self.gamma_i.zeroize();
        self.sigma_share.zeroize();
        for v in self.delta_shares.values_mut() {
            v.zeroize();
        }
        for v in self.zeta_shares.values_mut() {
            v.zeroize();
        }
    }
}

impl Drop for Tx25Presignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Tx25Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tx25Presignature")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

pub(crate) struct KeyMaterial {
    pub(crate) sk_decimal: Vec<u8>,
    pub(crate) raw_pks: Vec<ClPublicKey>,
    pub(crate) x_i: k256::Scalar,
    #[allow(dead_code)]
    pub(crate) public_key: k256::ProjectivePoint,
    pub(crate) public_shares: Vec<k256::ProjectivePoint>,
    pub(crate) threshold: u16,
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        self.sk_decimal.zeroize();
        self.x_i.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}
