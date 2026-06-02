// SPDX-License-Identifier: MIT OR Apache-2.0
//! Network simulation profiles for benchmark parametrization.
//!
//! These profiles capture representative real-world network conditions.
//! They are used by the benchmark harness (`tecdsa-bench`) to parametrize
//! round-trip measurements under different latency/loss settings.

/// A named set of network characteristics used to simulate real-world conditions.
#[derive(Debug, Clone)]
pub struct NetworkProfile {
    /// Human-readable name for this profile (e.g. `"LAN"`, `"satellite"`).
    pub name: &'static str,
    /// One-way latency in milliseconds (median).
    pub latency_ms: u32,
    /// Latency jitter in milliseconds (± half-range).
    pub jitter_ms: u32,
    /// Packet-loss rate in the range `[0.0, 1.0]`.
    pub loss_rate: f64,
    /// Available bandwidth in kilobits per second.
    pub bandwidth_kbps: u32,
}

impl NetworkProfile {
    /// Local-area network: sub-millisecond latency, no loss, ~1 Gbps.
    #[must_use]
    pub fn lan() -> Self {
        Self {
            name: "LAN",
            latency_ms: 1,
            jitter_ms: 0,
            loss_rate: 0.0,
            bandwidth_kbps: 1_000_000,
        }
    }

    /// Wide-area network (continental): ~50 ms latency, no loss, ~100 Mbps.
    #[must_use]
    pub fn wan() -> Self {
        Self {
            name: "WAN",
            latency_ms: 50,
            jitter_ms: 10,
            loss_rate: 0.0,
            bandwidth_kbps: 100_000,
        }
    }

    /// Lossy wide-area network: ~80 ms latency, 1 % loss, ~50 Mbps.
    #[must_use]
    pub fn lossy_wan() -> Self {
        Self {
            name: "lossy-WAN",
            latency_ms: 80,
            jitter_ms: 20,
            loss_rate: 0.01,
            bandwidth_kbps: 50_000,
        }
    }

    /// Geostationary satellite link: ~600 ms latency, 2 % loss, ~10 Mbps.
    #[must_use]
    pub fn satellite() -> Self {
        Self {
            name: "satellite",
            latency_ms: 600,
            jitter_ms: 50,
            loss_rate: 0.02,
            bandwidth_kbps: 10_000,
        }
    }

    /// Return an ordered list of all built-in profiles, from fastest to slowest.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::lan(),
            Self::wan(),
            Self::lossy_wan(),
            Self::satellite(),
        ]
    }
}
