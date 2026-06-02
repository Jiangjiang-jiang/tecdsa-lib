// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct SessionMetrics {
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub messages_sent: usize,
    pub messages_received: usize,
    pub bytes_per_round: BTreeMap<u16, usize>,
    pub round_durations: BTreeMap<u16, Duration>,
}
