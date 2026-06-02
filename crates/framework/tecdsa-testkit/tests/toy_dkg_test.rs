// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::PartyId;
use tecdsa_testkit::{toy_dkg::ToyDkgMachine, Orchestrator};

#[test]
fn toy_dkg_3_of_3_produces_agreed_public_key() {
    let n = 3u16;
    let machines: Vec<(PartyId, ToyDkgMachine)> = (0..n)
        .map(|i| (PartyId(i), ToyDkgMachine::new(PartyId(i), n)))
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");

    let public_keys: Vec<_> = results
        .iter()
        .map(|r| r.as_ref().unwrap().clone())
        .collect();

    // All parties must agree on the same combined public key.
    assert!(public_keys.windows(2).all(|w| w[0] == w[1]));
}
