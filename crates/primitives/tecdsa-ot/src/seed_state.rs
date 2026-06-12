use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::soft_spoken::HashOutput;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtSeedState {
    pub sender_correlation: Vec<bool>,
    pub sender_seeds: Vec<HashOutput>,
    pub receiver_seeds0: Vec<HashOutput>,
    pub receiver_seeds1: Vec<HashOutput>,
    pub usage_counter: u64,
}

impl OtSeedState {
    #[must_use]
    pub fn new(
        sender_correlation: Vec<bool>,
        sender_seeds: Vec<HashOutput>,
        receiver_seeds0: Vec<HashOutput>,
        receiver_seeds1: Vec<HashOutput>,
    ) -> Self {
        Self {
            sender_correlation,
            sender_seeds,
            receiver_seeds0,
            receiver_seeds1,
            usage_counter: 0,
        }
    }

    pub fn increment_counter(&mut self) -> u64 {
        self.usage_counter += 1;
        self.usage_counter
    }
}

impl Zeroize for OtSeedState {
    fn zeroize(&mut self) {
        for seed in &mut self.sender_seeds {
            seed.zeroize();
        }
        for seed in &mut self.receiver_seeds0 {
            seed.zeroize();
        }
        for seed in &mut self.receiver_seeds1 {
            seed.zeroize();
        }
        self.sender_correlation.clear();
        self.usage_counter = 0;
    }
}

impl Drop for OtSeedState {
    fn drop(&mut self) {
        self.zeroize();
    }
}
