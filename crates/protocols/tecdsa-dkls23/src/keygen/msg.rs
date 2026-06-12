use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR1Broadcast {
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR2Broadcast {
    pub salt: [u8; 32],
    pub point_commitments: Vec<Vec<u8>>,
    pub p_i_star: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenR2P2p {
    pub share: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Dkls23KeygenMsg {
    Round1Broadcast(KeygenR1Broadcast),
    Round2Broadcast(KeygenR2Broadcast),
    Round2P2p(KeygenR2P2p),
}
