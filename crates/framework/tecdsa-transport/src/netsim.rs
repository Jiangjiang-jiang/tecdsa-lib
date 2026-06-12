#[derive(Debug, Clone)]
pub struct NetworkProfile {
    pub name: &'static str,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_rate: f64,
    pub bandwidth_kbps: u32,
}

impl NetworkProfile {
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
