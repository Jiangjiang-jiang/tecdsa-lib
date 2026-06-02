// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_protocol::PartyId;
use tecdsa_transport::{InMemoryNetwork, Transport};

#[test]
fn in_memory_send_receive() {
    let mut net = InMemoryNetwork::new(3);
    let p0 = PartyId(0);
    let p1 = PartyId(1);
    let data = vec![1u8, 2, 3];
    net.send(p0, p1, data.clone());
    let received = net.receive(p1);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0, p0);
    assert_eq!(received[0].1, data);
}

#[test]
fn in_memory_broadcast() {
    let mut net = InMemoryNetwork::new(3);
    let p0 = PartyId(0);
    let data = vec![42u8];
    net.broadcast(p0, data.clone());
    for i in 0..3 {
        if i == 0 {
            continue;
        }
        let msgs = net.receive(PartyId(i));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].1, data);
    }
}

#[test]
fn in_memory_broadcast_sender_gets_no_message() {
    let mut net = InMemoryNetwork::new(3);
    let p0 = PartyId(0);
    net.broadcast(p0, vec![1, 2, 3]);
    let msgs = net.receive(p0);
    assert!(
        msgs.is_empty(),
        "sender should not receive its own broadcast"
    );
}

#[test]
fn in_memory_receive_drains_mailbox() {
    let mut net = InMemoryNetwork::new(2);
    let p0 = PartyId(0);
    let p1 = PartyId(1);
    net.send(p0, p1, vec![1]);
    net.send(p0, p1, vec![2]);
    let first = net.receive(p1);
    assert_eq!(first.len(), 2);
    let second = net.receive(p1);
    assert!(second.is_empty(), "mailbox should be drained after receive");
}

#[test]
fn in_memory_send_to_unknown_party_is_noop() {
    let mut net = InMemoryNetwork::new(2);
    // Party 99 does not exist; this should not panic.
    net.send(PartyId(0), PartyId(99), vec![1, 2, 3]);
}

#[test]
fn in_memory_party_count() {
    let net = InMemoryNetwork::new(5);
    assert_eq!(net.party_count(), 5);
}

#[test]
fn netsim_lan_profile_no_loss() {
    use tecdsa_transport::netsim::NetworkProfile;
    let profile = NetworkProfile::lan();
    assert!((profile.loss_rate - 0.0).abs() < f64::EPSILON);
    assert!(profile.latency_ms < 5);
}

#[test]
fn netsim_all_profiles_ordered_by_latency() {
    use tecdsa_transport::netsim::NetworkProfile;
    let profiles = NetworkProfile::all();
    let latencies: Vec<u32> = profiles.iter().map(|p| p.latency_ms).collect();
    let mut sorted = latencies.clone();
    sorted.sort_unstable();
    assert_eq!(
        latencies, sorted,
        "all() should be ordered from fastest to slowest"
    );
}

#[test]
fn netsim_satellite_has_loss() {
    use tecdsa_transport::netsim::NetworkProfile;
    let sat = NetworkProfile::satellite();
    assert!(sat.loss_rate > 0.0);
    assert!(sat.latency_ms >= 500);
}
