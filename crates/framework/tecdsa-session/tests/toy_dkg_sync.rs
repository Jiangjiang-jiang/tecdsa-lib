use tecdsa_core::{Result as TecdsaResult, TecdsaError};
use tecdsa_protocol::{Outgoing, PartyId, Recipient, StateMachine};
use tecdsa_session::{run_multi_party_sync, SessionRunConfig};
use tecdsa_testkit::{toy_dkg::ToyDkgMachine, Orchestrator};
use tecdsa_transport::InMemoryNetwork;

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

    for (i, res) in session_results.iter().enumerate() {
        assert!(
            res.is_ok(),
            "party {i} failed via SyncSession: {:?}",
            res.as_ref().err()
        );
    }

    let orch_result = Orchestrator::new(make_machines(n), 10)
        .run()
        .expect("orchestrator must succeed");

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum PingPongMsg {
    Ping,
    Pong,
}

#[derive(Debug)]
enum PingPongState {
    InitiatorWaitingForPong,
    ResponderWaitingForPing,
    Done,
}

#[derive(Debug)]
struct PingPongMachine {
    peer: PartyId,
    state: PingPongState,
    outgoing: Vec<Outgoing<PingPongMsg>>,
    round: u16,
}

impl PingPongMachine {
    fn initiator(peer: PartyId) -> Self {
        Self {
            peer,
            state: PingPongState::InitiatorWaitingForPong,
            outgoing: vec![Outgoing {
                to: Recipient::Party(peer),
                msg: PingPongMsg::Ping,
            }],
            round: 1,
        }
    }

    fn responder(peer: PartyId) -> Self {
        Self {
            peer,
            state: PingPongState::ResponderWaitingForPing,
            outgoing: Vec::new(),
            round: 0,
        }
    }
}

impl StateMachine for PingPongMachine {
    type Output = &'static str;
    type Inbound = PingPongMsg;
    type Outbound = PingPongMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> TecdsaResult<()> {
        if from != self.peer {
            return Err(TecdsaError::Other("unexpected sender".into()));
        }

        match (&self.state, msg) {
            (PingPongState::ResponderWaitingForPing, PingPongMsg::Ping) => {
                self.outgoing.push(Outgoing {
                    to: Recipient::Party(self.peer),
                    msg: PingPongMsg::Pong,
                });
                self.state = PingPongState::Done;
                self.round = 2;
                Ok(())
            }
            (PingPongState::InitiatorWaitingForPong, PingPongMsg::Pong) => {
                self.state = PingPongState::Done;
                self.round = 2;
                Ok(())
            }
            _ => Err(TecdsaError::Other("unexpected ping-pong message".into())),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.state, PingPongState::Done)
    }

    fn finish(self) -> TecdsaResult<Self::Output> {
        if self.is_done() {
            Ok("done")
        } else {
            Err(TecdsaError::Other("ping-pong did not complete".into()))
        }
    }

    fn current_round(&self) -> u16 {
        self.round
    }

    fn ia_report(&self) -> Option<&tecdsa_protocol::IaReport> {
        None
    }
}

#[test]
fn sync_session_two_party_ping_pong_accepts_peer_round_ahead() {
    let parties = [PartyId(0), PartyId(1)];
    let session_id = [0x24u8; 32];
    let mut network = InMemoryNetwork::new(2);

    let results = run_multi_party_sync(
        vec![
            (parties[0], PingPongMachine::initiator(parties[1])),
            (parties[1], PingPongMachine::responder(parties[0])),
        ],
        &mut network,
        session_id,
        SessionRunConfig::default(),
        4,
    );

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "party {i} failed in ping-pong session: {:?}",
            result.as_ref().err()
        );
    }
}
