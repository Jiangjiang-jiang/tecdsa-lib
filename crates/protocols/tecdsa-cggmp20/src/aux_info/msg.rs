use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_paillier::{zk::paillier_zk::no_small_factor as pi_fac, EncryptionKey};
use tecdsa_pedersen_mod::{PedersenModParams, PiMod, PiPrm};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound1 {
    pub commitment: HashCommitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound2 {
    pub paillier_ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub pi_prm: PiPrm,
    pub rho: [u8; 32],
    pub decommit_nonce: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound3 {
    pub pi_mod: PiMod,
    pub pi_fac: pi_fac::NiProof,
}

impl std::fmt::Debug for MsgRound3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsgRound3")
            .field("pi_mod", &"<PiMod>")
            .field("pi_fac", &"<NiProof>")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuxInfoMsg {
    Round1(MsgRound1),
    Round2(MsgRound2),
    Round3(MsgRound3),
}
