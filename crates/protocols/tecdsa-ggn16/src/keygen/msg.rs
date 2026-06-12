#![allow(non_snake_case)]

use elliptic_curve::CurveArithmetic;
use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_paillier::backend::Integer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenRound1Msg {
    pub commitment: HashCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct KeygenRound2Msg<C: CurveArithmetic> {
    pub y_i_bytes: Vec<u8>,
    pub nonce: [u8; 32],
    pub alpha_i: Integer,
    pub alpha_i_nonce: Integer,
    pub proof: Vec<u8>,
    #[serde(skip)]
    pub _marker: std::marker::PhantomData<C>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub enum Ggn16KeygenMsg<C: CurveArithmetic> {
    Round1(KeygenRound1Msg),
    Round2(KeygenRound2Msg<C>),
}
