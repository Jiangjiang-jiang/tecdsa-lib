// SPDX-License-Identifier: MIT OR Apache-2.0
//! Known-Answer-Test (KAT) runner utilities.
//!
//! KAT vectors are frozen at the time a protocol is finalised and stored as
//! JSON files.  Running them on every CI build catches regressions in wire
//! format, arithmetic, or serialisation without needing a live multi-party
//! session.

use serde::{Deserialize, Serialize};

/// A single KAT vector: a named input/output pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct KatVector {
    /// Human-readable name identifying this test case.
    pub name: String,
    /// Raw input bytes (protocol- and test-specific encoding).
    pub input: Vec<u8>,
    /// Expected output bytes that the implementation must reproduce exactly.
    pub expected_output: Vec<u8>,
}

/// Load KAT vectors from a JSON file at `path`.
///
/// # Panics
///
/// Panics if the file cannot be read or if its contents are not valid JSON
/// encoding of `Vec<KatVector>`.
#[must_use]
pub fn load_vectors(path: &std::path::Path) -> Vec<KatVector> {
    let data = std::fs::read(path).expect("failed to read KAT file");
    serde_json::from_slice(&data).expect("failed to parse KAT file")
}
