use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Versioned<T> {
    version: u16,
    payload: T,
}

impl<T> Versioned<T> {
    pub fn new(version: u16, payload: T) -> Self {
        Self { version, payload }
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_payload(self) -> T {
        self.payload
    }
}
