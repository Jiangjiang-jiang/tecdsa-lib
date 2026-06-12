use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KatVector {
    pub name: String,
    pub input: Vec<u8>,
    pub expected_output: Vec<u8>,
}

#[must_use]
pub fn load_vectors(path: &std::path::Path) -> Vec<KatVector> {
    let data = std::fs::read(path).expect("failed to read KAT file");
    serde_json::from_slice(&data).expect("failed to parse KAT file")
}
