// SPDX-License-Identifier: MIT OR Apache-2.0
//! Integration test: run a toy DKG through the `SessionRunner` wire
//! encode/decode path via `run_multi_party_sync`, then compare results
//! against the direct `Orchestrator` (which bypasses wire encoding).

use tecdsa_protocol::PartyId;
use tecdsa_session::{run_multi_party_sync, SessionRunConfig};
use tecdsa_testkit::toy_dkg::ToyDkgMachine;
use tecdsa_testkit::Orchestrator;
use tecdsa_transport::InMemoryNetwork;

/// Build the standard set of `(PartyId, ToyDkgMachine)` pairs.
fn make_machines(n: u16) -> Vec<(PartyId, ToyDkgMachine)> {
    (0..n)
        .map(|i| (PartyId(i), ToyDkgMachine::new(PartyId(i), n)))
        .collect()
}

#[test]
fn sync_session_toy_dkg_3_parties() {
    let n = 3u16;
    let session_id = [0xABu8; 32];
    let mut network = InMemoryNetwork::new(n);

    let session_results = run_multi_party_sync(
        make_machines(n),
        &mut network,
        session_id,
        SessionRunConfig::default(),
        10,
    );

    // All three parties must succeed.
    for (i, res) in session_results.iter().enumerate() {
        assert!(
            res.is_ok(),
            "party {i} failed via SyncSession: {:?}",
            res.as_ref().err()
        );
    }

    // Run via Orchestrator for comparison (no wire encoding).
    let orch_result = Orchestrator::new(make_machines(n), 10)
        .run()
        .expect("orchestrator must succeed");

    // Both paths must produce identical combined public keys.
    for (i, (sr, or)) in session_results.iter().zip(orch_result.iter()).enumerate() {
        assert_eq!(
            sr.as_ref().unwrap(),
            or.as_ref().unwrap(),
            "party {i}: SyncSession output differs from Orchestrator output"
        );
    }
}

#[test]
fn sync_session_toy_dkg_5_parties() {
    let n = 5u16;
    let session_id = [0xCDu8; 32];
    let mut network = InMemoryNetwork::new(n);

    let session_results = run_multi_party_sync(
        make_machines(n),
        &mut network,
        session_id,
        SessionRunConfig::default(),
        10,
    );

    for (i, res) in session_results.iter().enumerate() {
        assert!(
            res.is_ok(),
            "party {i} failed via SyncSession: {:?}",
            res.as_ref().err()
        );
    }

    // All parties must agree on the same combined key.
    let first = session_results[0].as_ref().unwrap();
    for (i, res) in session_results.iter().enumerate().skip(1) {
        assert_eq!(
            first,
            res.as_ref().unwrap(),
            "party {i} disagrees with party 0"
        );
    }
}

#[test]
fn sync_session_toy_dkg_2_parties() {
    let n = 2u16;
    let session_id = [0x42u8; 32];
    let mut network = InMemoryNetwork::new(n);

    let session_results = run_multi_party_sync(
        make_machines(n),
        &mut network,
        session_id,
        SessionRunConfig::default(),
        10,
    );

    for (i, res) in session_results.iter().enumerate() {
        assert!(res.is_ok(), "party {i} failed: {:?}", res.as_ref().err());
    }

    let orch_result = Orchestrator::new(make_machines(n), 10)
        .run()
        .expect("orchestrator must succeed");
    for (i, (sr, or)) in session_results.iter().zip(orch_result.iter()).enumerate() {
        assert_eq!(
            sr.as_ref().unwrap(),
            or.as_ref().unwrap(),
            "party {i}: mismatch between SyncSession and Orchestrator"
        );
    }
}
