#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23SignMsg {
    PartialSig(Vec<u8>),
}
