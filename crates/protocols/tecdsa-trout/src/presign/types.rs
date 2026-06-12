use tecdsa_class_group::zk::{r_cl_dl_ec::RClDlEcProof, r_com_kwlg::RComKwlgProof};
use tecdsa_evrf::{EvrfOutput, EvrfProof};
use zeroize::Zeroize;

pub struct TroutRound1State {
    pub party_index: u16,
    pub k_i: k256::Scalar,
    pub u_i: k256::Scalar,
    pub alpha_i: Vec<u8>,
    pub beta_i: Vec<u8>,
    pub l_i: k256::Scalar,
    pub l_i_delta_i: Vec<u8>,
}

impl Zeroize for TroutRound1State {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.u_i.zeroize();
        self.alpha_i.zeroize();
        self.beta_i.zeroize();
        self.l_i.zeroize();
        self.l_i_delta_i.zeroize();
    }
}

impl Drop for TroutRound1State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct TroutRound1Broadcast {
    pub party_index: u16,
    pub r_i_bytes: Vec<u8>,
    pub evrf_output: EvrfOutput<k256::Secp256k1>,
    pub evrf_proof: EvrfProof<k256::Secp256k1>,
    pub kt_c1_abc: (String, String, String),
    pub kt_c2_abc: (String, String, String),
    pub u_com_abc: (String, String, String),
    pub ct_scaled_c1_abc: (String, String, String),
    pub ct_scaled_c2_abc: (String, String, String),
    pub pi_cl_ec: RClDlEcProof,
    pub pi_com_kwlg: RComKwlgProof,
}

pub struct TroutPresignOutput {
    pub party_index: u16,
    pub big_r: k256::ProjectivePoint,
    pub r_scalar: k256::Scalar,
    pub k_i: k256::Scalar,
    pub u_i: k256::Scalar,
    pub alpha_i: Vec<u8>,
    pub beta_i: Vec<u8>,
    pub l_i: k256::Scalar,
    pub l_i_delta_i: Vec<u8>,
    pub all_broadcasts: Vec<TroutRound1Broadcast>,
}

impl Zeroize for TroutPresignOutput {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.u_i.zeroize();
        self.alpha_i.zeroize();
        self.beta_i.zeroize();
        self.l_i.zeroize();
        self.l_i_delta_i.zeroize();
    }
}

impl Drop for TroutPresignOutput {
    fn drop(&mut self) {
        self.zeroize();
    }
}
