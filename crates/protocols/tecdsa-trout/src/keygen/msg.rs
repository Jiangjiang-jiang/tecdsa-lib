use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutKeygenMsg {
    Round1(Vec<u8>),
    Round2Bcast(Vec<u8>),
    Round2Share(Vec<u8>),
    Round3(Vec<u8>),
}
