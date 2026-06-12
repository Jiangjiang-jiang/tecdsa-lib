use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_paillier::{backend::Integer, threshold::PartialDecryption};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ggn16SignMsg {
    Round1(SignRound1Msg),
    Round2(SignRound2Msg),
    Round3(SignRound3Msg),
    Round4(SignRound4Msg),
    Round5(SignRound5Msg),
    Round6(SignRound6Msg),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound1Msg {
    pub commitment: HashCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound2Msg {
    pub u_i: Integer,
    pub v_i: Integer,
    pub nonce: [u8; 32],
    pub homo_mult_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound3Msg {
    pub commitment: HashCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound4Msg {
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,
    pub nonce: [u8; 32],
    pub nonce_consist_proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound5Msg {
    pub partial_w: PartialDecryption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRound6Msg {
    pub partial_sigma: PartialDecryption,
}
