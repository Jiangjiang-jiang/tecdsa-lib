use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmy23KeygenMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Round3(Vec<u8>),
    Round4(Vec<u8>),
}
