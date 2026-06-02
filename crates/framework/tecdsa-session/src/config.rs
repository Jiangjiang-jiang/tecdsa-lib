// SPDX-License-Identifier: MIT OR Apache-2.0
use std::path::PathBuf;
use std::time::Duration;

pub struct SessionRunConfig {
    pub max_rounds: u16,
    pub round_timeout: Duration,
    pub retry_policy: RetryPolicy,
    pub checkpoint_dir: Option<PathBuf>,
    pub protocol_id: u16,
}

pub struct RetryPolicy {
    pub max_retries: u8,
    pub base_delay: Duration,
}

impl Default for SessionRunConfig {
    fn default() -> Self {
        Self {
            max_rounds: 20,
            round_timeout: Duration::from_secs(30),
            retry_policy: RetryPolicy {
                max_retries: 3,
                base_delay: Duration::from_millis(100),
            },
            checkpoint_dir: None,
            protocol_id: 0,
        }
    }
}
