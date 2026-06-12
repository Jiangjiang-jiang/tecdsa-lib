#![forbid(unsafe_code)]

mod slip10;

pub use slip10::{
    derive_child_public, derive_child_share, derive_master, ChainCode, DerivationIndex,
};
