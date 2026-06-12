use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProtocolTiming {
    pub protocol: String,
    pub n: u16,
    pub t: u16,
    pub phases: Vec<PhaseTiming>,
}

#[derive(Debug, Clone)]
pub struct PhaseTiming {
    pub name: String,
    pub rounds: u16,
    pub duration: Duration,
}

pub struct PhaseTimer {
    name: String,
    rounds: u16,
    start: Instant,
}

impl PhaseTimer {
    pub fn start(name: &str, rounds: u16) -> Self {
        Self {
            name: name.to_string(),
            rounds,
            start: Instant::now(),
        }
    }

    pub fn stop(self) -> PhaseTiming {
        PhaseTiming {
            name: self.name,
            rounds: self.rounds,
            duration: self.start.elapsed(),
        }
    }
}

impl ProtocolTiming {
    pub fn new(protocol: &str, n: u16, t: u16) -> Self {
        Self {
            protocol: protocol.to_string(),
            n,
            t,
            phases: Vec::new(),
        }
    }

    pub fn add_phase(&mut self, phase: PhaseTiming) {
        self.phases.push(phase);
    }

    pub fn total_duration(&self) -> Duration {
        self.phases.iter().map(|p| p.duration).sum()
    }

    pub fn phase_duration(&self, name: &str) -> Option<Duration> {
        self.phases
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.duration)
    }

    pub fn offline_duration(&self) -> Option<Duration> {
        self.phase_duration("Presign")
    }

    pub fn online_duration(&self) -> Option<Duration> {
        self.phase_duration("OnlineSign")
    }
}
