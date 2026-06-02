// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_gg18::Gg18;
use tecdsa_protocol::Protocol;

#[test]
fn protocol_metadata_is_correct() {
    assert_eq!(Gg18::METADATA.name, "GG18");
    assert_eq!(Gg18::METADATA.version, "1.0");
    assert_eq!(Gg18::METADATA.primitive, "Threshold ECDSA");
    assert_eq!(Gg18::METADATA.signing_rounds_paper, 8);
    assert_eq!(
        Gg18::METADATA.security_model,
        "Malicious with dishonest majority"
    );
}

#[test]
fn noop_machines_are_immediately_done() {
    use tecdsa_protocol::{NoOpMachine, StateMachine};

    let aux = NoOpMachine::new();
    assert!(aux.is_done());
    assert_eq!(aux.current_round(), 0);
    assert!(aux.finish().is_ok());
}
